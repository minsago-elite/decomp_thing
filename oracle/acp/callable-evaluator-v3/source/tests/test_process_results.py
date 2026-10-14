"""Synthetic process evidence only; no child process or native tool invocation."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
import tempfile
import shutil
import json
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import evaluate_candidate_v3 as e


def receipt(code=0,stdout=b'ok',stderr=b''):
    return {**{k:True for k in e.PROOF_FLAGS},'exitCode':code,'stdout':stdout,'stderr':stderr,'rootReaped':True,'finalAbsenceVerified':True,'kernelScope':{'finalAbsenceVerified':True},'timedOut':False,'outputExceeded':False,'infrastructureFailure':False,'bounds':{'phase':'runtime'}}


def observations():
    return [{'id':i,'family':family,'process':e.process_observation(receipt())} for i,family in enumerate(e.SCENARIO_FAMILIES)]


class ProcessResults(unittest.TestCase):
    def test_exact_nonzero_and_signal_completed_termination(self):
        for code in (0,7,-11):
            raw=receipt(code);self.assertEqual(e.compare_process(e.process_observation(raw),raw)[0],'matched')
        self.assertEqual(e.compare_process(e.process_observation(receipt(7)),receipt(0))[0],'mismatched')
        self.assertEqual(e.compare_process(e.process_observation(receipt(-7)),receipt(7))[0],'mismatched')
    def test_each_missing_or_malformed_stream_is_unknown_not_empty_match(self):
        expected=e.process_observation(receipt(stdout=b'',stderr=b''))
        for field in ('stdout','stderr'):
            for malformed in (None,'',bytearray()):
                raw=receipt(stdout=b'',stderr=b'');raw[field]=malformed
                status,process=e.compare_process(expected,raw)
                self.assertEqual(status,'unknown');self.assertFalse(process['completed']);self.assertIsNone(process[field+'Hex'])
            raw=receipt(stdout=b'',stderr=b'');del raw[field]
            status,process=e.compare_process(expected,raw)
            self.assertEqual(status,'unknown');self.assertIsNone(process[field+'Hex'])
        self.assertEqual(e.compare_process(expected,receipt(stdout=b'',stderr=b''))[0],'matched')

    def test_historical_missing_stream_match_is_rejected_by_current_source(self):
        import ast,hashlib
        old=e.BASE.parents[3]/'build/acp-decomp-effectiveness/callable-library-v3/evaluate_candidate_v3.py'
        raw=old.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'40dd84136ed4018b916eb5b461ed0ebb97a0701f0b724056d58f683a97d330fa')
        functions=[node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef) and node.name in ('process_observation','compare_process')]
        namespace={'PROOF_FLAGS':e.PROOF_FLAGS};exec(compile(ast.Module(body=functions,type_ignores=[]),'historical-missing-stream-control','exec'),namespace)
        raw=receipt(stdout=b'',stderr=b'');expected=e.process_observation(raw)
        del raw['stdout'];del raw['stderr']
        self.assertEqual(namespace['compare_process'](expected,raw)[0],'matched')
        self.assertEqual(e.compare_process(expected,raw)[0],'unknown')

    def test_marker_bytes_are_never_stripped_or_authority(self):
        for marker in (b'ACP_V2_LOAD_OK\nACP_V2_CALL\n',b'REFUSED_CONSTRUCTOR_EXECUTED\n'):
            self.assertEqual(e.compare_process(e.process_observation(receipt()),receipt(stderr=marker))[0],'mismatched')
            item=e.scenario_entry(observations()[0],receipt(stderr=marker),True)
            self.assertEqual(item['apiEntryObservation'],{'status':'unverified','value':None})
    def test_each_missing_proof_is_unknown(self):
        for flag in (*e.PROOF_FLAGS,'timedOut','outputExceeded','infrastructureFailure','finalAbsenceVerified'):
            raw=receipt();del raw[flag]
            self.assertEqual(e.compare_process(e.process_observation(receipt()),raw)[0],'unknown',flag)
    def test_timeout_overflow_and_cleanup_preserve_partial_bytes(self):
        for key in ('timedOut','outputExceeded','infrastructureFailure'):
            raw=receipt(stdout=b'partial');raw[key]=True
            status,actual=e.compare_process(e.process_observation(receipt(stdout=b'partial')),raw)
            self.assertEqual(status,'unknown');self.assertEqual(actual['stdoutHex'],b'partial'.hex())
        raw=receipt();raw['kernelScope']['finalAbsenceVerified']=False
        self.assertFalse(e.process_observation(raw)['completed'])
    def test_known_mismatch_survives_unknown(self):
        rows=[e.scenario_entry(o,receipt(),True) for o in observations()]
        rows[0]=e.scenario_entry(observations()[0],receipt(stdout=b'different'),True)
        rows[1]=e.scenario_entry(observations()[1],None,True)
        summary=e.summarize(rows,True)
        self.assertEqual(summary['behaviorStatus'],'failed');self.assertEqual(summary['completedScenarioProcessCount'],23)
        self.assertEqual(summary['unknownScenarioProcessCount'],1)
    def test_all_unknown_and_all_matched_and_refusal(self):
        for admitted,raw,status in ((True,None,'unknown'),(True,receipt(),'passed'),(False,None,'not-attempted')):
            summary=e.summarize([e.scenario_entry(o,raw,admitted) for o in observations()],admitted)
            self.assertEqual(summary['behaviorStatus'],status);self.assertIsNone(summary['apiEntryCount'])
            if raw is None:self.assertIsNone(summary['processBehaviorRate'])
    def test_exact_ids_families_and_admission_are_required(self):
        rows=[e.scenario_entry(o) for o in observations()]
        for field,value in (('id',1),('family','acp_fold'),('runtimeRequested',True)):
            changed=deepcopy(rows);changed[0][field]=value
            with self.assertRaises(ValueError):e.summarize(changed,False)
    def test_incomplete_expected_gcc_keeps_declaration_and_both_checks(self):
        trusted=Path(__file__).resolve().parents[1].parents[3]/'build/acp-decomp-effectiveness/callable-library-v3/static-process'
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);(root/'private').mkdir()
            for name in ('original.c','original.h'):(root/'private'/name).write_text('synthetic only')
            shutil.copytree(e.BASE/'contracts',root/'contracts')
            for name in ('candidate.c','helper','caller','observations.json'):(root/name).write_text('synthetic only')
            def directory(path):path.mkdir(parents=True);return path
            def write(path,value):path.write_text(json.dumps(value))
            def fake_run(*args,**kwargs):return {'status':'passed'},receipt()
            def assertions(source,value):
                if source.name=='expected.i':raise ValueError('missing independent GCC binding')
                return 'synthetic assertion'
            with patch.object(e,'BASE',root),patch.object(e,'private_directory',side_effect=directory),patch.object(e,'write_json',side_effect=write),patch.object(e,'validated_observations',return_value=observations()),patch.object(e,'verify_visible'),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'run',side_effect=fake_run),patch.object(e,'probe',return_value={'status':'supported','interfaces':{'acp_state':{}}}),patch.object(e,'compare_descriptors',return_value={'status':'passed','accepted':True}),patch.object(e,'layout_assertions',side_effect=assertions),patch.object(e,'resolve_declaration',return_value={'sizeBits':64}),patch.object(e,'export_inventory',return_value={'status':'passed'}):
                report=e.evaluate(root/'candidate.c',root/'output',root/'helper',root/'caller',root,root/'observations.json')
            self.assertEqual(report['phases']['declarations']['status'],'passed')
            self.assertEqual(report['phases']['gccAssertions']['status'],'unknown')
            checks=json.loads((root/'output/gcc-assertions.json').read_bytes())['checks']
            self.assertEqual(checks['expected']['status'],'unknown');self.assertEqual(checks['candidate']['status'],'passed')
            self.assertEqual(report['runtimeRequestCount'],0)

    def test_run_mocked_nonzero_is_complete_failure_not_unknown(self):
        with patch.object(e,'bounded_run',return_value=receipt(7)),patch.object(e,'public_result',side_effect=lambda r:r):
            status,result=e.run(['synthetic'],Path('/not-used'),phase='runtime')
        self.assertEqual(status['status'],'failed');self.assertTrue(e.process_observation(result)['completed'])


if __name__=='__main__':unittest.main()
