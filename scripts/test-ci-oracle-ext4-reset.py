#!/usr/bin/env python3
"""Unprivileged transport/deadline controls; these do not qualify mounted reset."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'scripts/ci-oracle-ext4-reset.py'
SPEC = importlib.util.spec_from_file_location('reset_fixture', PATH)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        directory = ROOT / 'build/issue933-evidence/fixture-tests'
        directory.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.summary = {'schemaVersion': 1, 'completed': [], 'startBudget': {
            'bootId': '11111111-1111-4111-8111-111111111111', 'sessionId': 'a' * 64,
            'timestampsMonotonicNs': [], 'lastTerminalMonotonicNs': 0}}

    def test_fifo_snapshot_refuses_under_outer_process_deadline(self):
        fifo = self.directory / 'fifo'
        os.mkfifo(fifo)
        code = ('import importlib.util,sys; s=importlib.util.spec_from_file_location("f",sys.argv[1]); '
                'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                'm.read_regular(m.Path(sys.argv[2]),4096)')
        result = subprocess.run([sys.executable, '-B', '-c', code, str(PATH), str(fifo)],
                                capture_output=True, timeout=2)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b'owned regular file', result.stderr)

    def child(self, code):
        return subprocess.Popen([sys.executable, '-B', '-c', code], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, process_group=0)

    def test_bounded_child_success_captures_and_reaps(self):
        process = self.child('print("measured")')
        result = FIXTURE.collect_process(process, timeout=2, maximum=128)
        self.assertEqual((0, b'measured\n', b''), result)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def test_output_overflow_kills_and_reaps_child(self):
        process = self.child('import os,time; os.write(1,b"x"*8192); time.sleep(30)')
        with self.assertRaisesRegex(FIXTURE.QualificationError, 'output exceeded'):
            FIXTURE.collect_process(process, timeout=2, maximum=32)
        self.assertEqual(-9, process.returncode)

    def test_inherited_pipe_cannot_extend_outer_deadline(self):
        process = self.child('import os,time; p=os.fork(); time.sleep(30) if p==0 else os._exit(0)')
        with self.assertRaisesRegex(FIXTURE.QualificationError, 'deadline'):
            FIXTURE.collect_process(process, timeout=.2, maximum=64)
        self.assertEqual(0, process.returncode)

    def pace(self, now, summary=None):
        summary = copy.deepcopy(summary or self.summary)
        clock = [now]
        writes = []
        def sleep(seconds):
            clock[0] += round(seconds * 1_000_000_000)
        with mock.patch.object(FIXTURE, 'load_summary', return_value=summary), \
             mock.patch.object(FIXTURE.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
             mock.patch.object(FIXTURE.time, 'sleep', side_effect=sleep) as sleeper, \
             mock.patch.object(FIXTURE, 'write_owned', side_effect=lambda path,data,*args: writes.append(json.loads(data))):
            FIXTURE.pace_submission()
        return sleeper, writes

    def test_first_submission_is_charged_before_broker(self):
        sleeper, writes = self.pace(5_000_000_000)
        sleeper.assert_not_called()
        self.assertEqual([5_000_000_000], writes[0]['startBudget']['timestampsMonotonicNs'])

    def test_submission_spacing_is_persisted(self):
        self.summary['startBudget']['timestampsMonotonicNs'] = [5_000_000_000]
        sleeper, writes = self.pace(6_000_000_000)
        sleeper.assert_called_once_with(1.1)
        self.assertEqual([5_000_000_000, 7_100_000_000], writes[0]['startBudget']['timestampsMonotonicNs'])

    def test_queued_start_delay_is_paced_from_actual_terminal_observation(self):
        self.summary['startBudget'].update(timestampsMonotonicNs=[5_000_000_000], lastTerminalMonotonicNs=15_000_000_000)
        sleeper, writes = self.pace(15_500_000_000)
        sleeper.assert_called_once_with(1.6)
        self.assertEqual(17_100_000_000, writes[0]['startBudget']['timestampsMonotonicNs'][-1])

    def test_sixty_four_attempt_limit_refuses_without_sleep_or_write(self):
        self.summary['startBudget']['timestampsMonotonicNs'] = [1+i*2_100_000_000 for i in range(64)]
        with mock.patch.object(FIXTURE, 'load_summary', return_value=self.summary), \
             mock.patch.object(FIXTURE.time, 'sleep') as sleep, mock.patch.object(FIXTURE, 'write_owned') as write:
            with self.assertRaisesRegex(FIXTURE.QualificationError, 'budget exhausted'):
                FIXTURE.pace_submission()
        sleep.assert_not_called(); write.assert_not_called()

    def test_regressed_clock_refuses_without_counter_reset(self):
        self.summary['startBudget']['lastTerminalMonotonicNs'] = 10
        with self.assertRaisesRegex(FIXTURE.QualificationError, 'clock regressed'):
            self.pace(9)
        self.assertEqual(10, self.summary['startBudget']['lastTerminalMonotonicNs'])

    def test_summary_refuses_missing_terminal_changed_boot_session_or_bad_spacing(self):
        parser = types.SimpleNamespace(parse_canonical=json.loads, boot_id=lambda:self.summary['startBudget']['bootId'])
        changes = [lambda b:b.pop('lastTerminalMonotonicNs'), lambda b:b.update(bootId='bad'),
                   lambda b:b.update(sessionId='b'*64), lambda b:b.update(timestampsMonotonicNs=[1,2])]
        for change in changes:
            altered = copy.deepcopy(self.summary); change(altered['startBudget'])
            with self.subTest(budget=altered), mock.patch.object(FIXTURE,'core',return_value=parser), \
                 mock.patch.object(FIXTURE,'read_regular',return_value=FIXTURE.canonical(altered)), \
                 mock.patch.object(FIXTURE,'load_fixture',return_value={'sessionId':'a'*64}):
                with self.assertRaises(FIXTURE.QualificationError): FIXTURE.load_summary()

    def test_terminal_observation_persists_without_inventing_submission(self):
        with mock.patch.object(FIXTURE,'load_summary',return_value=self.summary), \
             mock.patch.object(FIXTURE.time,'monotonic_ns',return_value=99), \
             mock.patch.object(FIXTURE,'write_owned') as write:
            FIXTURE.record_terminal()
        saved=json.loads(write.call_args.args[1])
        self.assertEqual(99,saved['startBudget']['lastTerminalMonotonicNs'])
        self.assertEqual([],saved['startBudget']['timestampsMonotonicNs'])

    def test_case_cannot_overwrite_evidence_before_all_artifacts_delivered(self):
        installation={'completed':[{'caseId':'K01'}], 'active':{'finished':True,'retrieved':['events.json']}}
        with self.assertRaisesRegex(FIXTURE.QualificationError,'not been delivered'):
            FIXTURE.prepare_case(installation,'K02')

    def test_case_order_keeps_teardown_after_candidate_cutpoints(self):
        with self.assertRaisesRegex(FIXTURE.QualificationError,'case order'):
            FIXTURE.prepare_case({'completed':[{}]*29,'active':None},'K30')

    def test_incomplete_case_cannot_get_passing_receipt(self):
        case=types.SimpleNamespace(active={'finished':False,'outcome':'prepared'},case_id='K28')
        with self.assertRaisesRegex(FIXTURE.QualificationError,'required outcome'):
            FIXTURE.finish_case(case)

    def test_artifact_enum_refuses_before_reading(self):
        with mock.patch.object(FIXTURE,'read_regular') as read:
            with self.assertRaises(FIXTURE.QualificationError):
                FIXTURE.artifact(types.SimpleNamespace(active={'finished':True}), '../state.json')
        read.assert_not_called()

    def test_probe_canary_matches_operation_identity(self):
        token='a'*64
        path=FIXTURE.probe_canary('K31',token,'hold-canary',str(FIXTURE.ROOT/'public/g-0000000000000001/scratch'))
        identity=FIXTURE.digest(f'K31:{token}:hold-canary'.encode())
        self.assertEqual('.decomp-oracle-lease-'+identity,path.parent.parent.name)
        with self.assertRaises(FIXTURE.QualificationError):
            FIXTURE.probe_canary('K31',token,'hold-canary','/tmp/unowned')


if __name__=='__main__':
    unittest.main()
