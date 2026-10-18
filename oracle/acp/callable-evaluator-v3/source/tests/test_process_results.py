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
import build_contract as contract
from static_test_support import historical_namespace, static_temp


def receipt(code=0,stdout=b'ok',stderr=b'',*,phase='runtime',caller='/synthetic/caller',caller_sha='a'*64,attempt='a'*32,input_pins=None,helper_identity=(90,93)):
    """Authored inert protocol records; no assertion of a real launch."""
    import hashlib
    from test_identity_graph import completed_result
    import bounded_runtime as runtime
    raw=completed_result(stdout,stderr,code)
    raw['bounds']={'phase':phase,'profileSha256':e.digest(e.BASE/'contracts/candidate-build-profile.json')}
    expected=raw['workerProofBindings']['expected'];expected.update(phase=phase,attempt=attempt)
    if input_pins is not None:
        target=input_pins[caller];expected.update(targetDevice=target['device'],targetInode=target['inode'])
    if phase=='probe':expected.update(targetDevice=helper_identity[0],targetInode=helper_identity[1])
    rows=[json.loads(line) for line in raw['workerProofRaw'].splitlines()]
    for row in rows:row.update(p=phase,a=attempt)
    rows[0].update(ed=expected['targetDevice'],ei=expected['targetInode'],od=expected['targetDevice'],oi=expected['targetInode'])
    if phase == 'runtime':
        library_path = next((name for name in (input_pins or {}) if name != caller), '/synthetic/libcandidate.so')
        library_pin = (input_pins or {}).get(library_path, {'sha256':'c'*64})
        expected['library'] = {'device':91,'inode':92,'size':3,'sha256':library_pin['sha256'],'sourcePath':library_path}
        rows[0]['l'] = [91,92,3]
    raw['workerProofRaw']=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in rows)
    raw['workerProof']['proofSha256']=hashlib.sha256(raw['workerProofRaw']).hexdigest()
    pins=raw['launchInputPins'];target=pins.pop('/authored/worker');target['sha256']=caller_sha;pins[caller]=target
    pins['/synthetic/libcandidate.so']={'device':9,'inode':10,'mode':256,'sha256':'c'*64}
    if input_pins is not None:pins.update(deepcopy(input_pins))
    if phase=='probe':pins['/proc/123/fd/40']={'device':helper_identity[0],'inode':helper_identity[1],'mode':0o500,'sha256':caller_sha}
    pins[str(runtime.BASE/'contracts/candidate-build-profile.json')]['sha256']=raw['bounds']['profileSha256']
    raw['workerProofBindings']['targetSha256']=caller_sha
    raw['workerProofBindings']['launchPinsSha256']=hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    return raw


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
        namespace=historical_namespace(PROOF_FLAGS=e.PROOF_FLAGS)
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
        trusted=static_temp('static-process')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);(root/'private').mkdir()
            for name in ('original.c','original.h'):(root/'private'/name).write_text('synthetic only')
            shutil.copytree(e.BASE/'contracts',root/'contracts')
            for name in ('candidate.c','helper','caller','observations.json'):(root/name).write_text('synthetic only')
            admitted_profile=contract._read_profile_snapshot()
            def directory(path):path.mkdir(parents=True);return path
            def write(path,value):
                raw=json.dumps(value).encode('utf-8');path.write_bytes(raw)
                return e.hashlib.sha256(raw).hexdigest()
            def fake_run(argv,work,**kwargs):
                if '-o' in argv:
                    target=argv[argv.index('-o')+1]
                    target=work/Path(target).name
                    target.write_bytes(b'synthetic compiler output')
                return {'status':'passed'},receipt()
            def assertions(source,value):
                if source.name=='expected.i':raise ValueError('missing independent GCC binding')
                return 'synthetic assertion'
            with patch.object(e,'BASE',root),patch.object(e,'private_directory',side_effect=directory),patch.object(e,'write_json',side_effect=write),patch.object(e,'validated_observations',return_value=observations()),patch.object(e,'verified_visible_snapshot',return_value=admitted_profile),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'run',side_effect=fake_run),patch.object(e,'probe',return_value={'status':'supported','interfaces':{'acp_state':{}}}),patch.object(e,'compare_descriptors',return_value={'status':'passed','accepted':True}),patch.object(e,'layout_assertions',side_effect=assertions),patch.object(e,'resolve_declaration',return_value={'sizeBits':64}),patch.object(e,'export_inventory',return_value={'status':'passed'}):
                report=e.evaluate(root/'candidate.c',root/'output',root/'helper',root/'caller',root,root/'observations.json')
            self.assertEqual(report['phases']['declarations']['status'],'passed')
            self.assertEqual(report['phases']['gccAssertions']['status'],'unknown')
            checks=json.loads((root/'output/gcc-assertions.json').read_bytes())['checks']
            self.assertEqual(checks['expected']['status'],'unknown');self.assertEqual(checks['candidate']['status'],'passed')
            self.assertEqual(report['runtimeRequestCount'],0)
            for name,sha in report['evidenceFiles'].items():
                self.assertEqual(e.hashlib.sha256((root/'output'/name).read_bytes()).hexdigest(),sha)

    def test_worker_proof_bindings_and_launcher_failures_are_unknown(self):
        expected=e.process_observation(receipt())
        for key in ('workerProofRaw','workerProofBindings','launchInputPins','workerTermination','launcherExitCode','provisioningOnly'):
            raw=receipt();del raw[key]
            status,obs=e.compare_process(expected,raw)
            self.assertEqual(status,'unknown',key);self.assertIsNone(obs['termination'])
        for change in ('wrapper','raw','target','profile','phase'):
            raw=receipt()
            if change=='wrapper':raw['launcherExitCode']=1
            elif change=='raw':raw['workerProofRaw']+=b'x'
            elif change=='target':raw['workerProofBindings']['targetSha256']='f'*64
            elif change=='profile':raw['bounds']['profileSha256']=None
            else:raw=receipt(phase='compiler')
            self.assertEqual(e.compare_process(expected,raw)[0],'unknown',change)
        self.assertEqual(e.compare_process(expected,receipt(attempt='b'*32))[0],'matched')
        forged=deepcopy(expected);forged['termination']['value']=7
        self.assertFalse(e.observation_complete(forged))

    def test_run_requires_requested_phase_current_profile_and_containment(self):
        for raw in (receipt(phase='runtime'),receipt(phase='compiler')):
            phase='compiler' if raw['bounds']['phase']=='runtime' else 'runtime'
            with patch.object(e,'bounded_run',return_value=raw):
                status,_=e.run(['/usr/bin/bwrap'],Path('/not-used'),phase=phase)
            self.assertEqual(status['status'],'unknown')
        raw=receipt();raw['bounds']['profileSha256']='f'*64
        with patch.object(e,'bounded_run',return_value=raw):
            self.assertEqual(e.run(['/usr/bin/bwrap'],Path('/not-used'),phase='runtime')[0]['status'],'unknown')
        with patch.object(e,'bounded_run',side_effect=AssertionError('must not launch host argv')):
            self.assertEqual(e.run(['/usr/bin/gcc'],Path('/not-used'))[0]['status'],'unknown')

    def test_compiler_inputs_overlay_exact_isolated_leaf_and_preserve_profile_argv(self):
        trusted=static_temp('static-process')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            leaf=Path(temporary);source=leaf/'candidate.c';source.write_bytes(b'authored inert source')
            argv=e.load_profile()['commands']['preprocess']
            recipe=e.phase_command(leaf,argv,(source,))
            self.assertEqual(recipe[-len(argv):],argv)
            at=recipe.index('--bind');self.assertEqual(recipe[at+1:at+3],[str(leaf),'/work'])
            self.assertIn(['--ro-bind',str(source),'/work/candidate.c'],[recipe[n:n+3] for n in range(len(recipe))])
            self.assertGreater(recipe.index(str(source)),at)
            with self.assertRaises(ValueError):e.phase_command(leaf,argv,(e.BASE/'evaluate_candidate_v3.py',))

    def test_run_mocked_nonzero_is_complete_failure_not_unknown(self):
        with patch.object(e,'bounded_run',return_value=receipt(7)),patch.object(e,'public_result',side_effect=lambda r:r):
            status,result=e.run(['/usr/bin/bwrap'],Path('/not-used'),phase='runtime')
        self.assertEqual(status['status'],'failed');self.assertTrue(e.process_observation(result)['completed'])


if __name__=='__main__':unittest.main()
