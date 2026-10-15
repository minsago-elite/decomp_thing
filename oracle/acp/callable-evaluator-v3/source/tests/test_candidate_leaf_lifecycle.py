"""Pure evaluator snapshot and exact-owned leaf lifecycle controls; no processes."""
import hashlib
import json
import os
import stat
from types import SimpleNamespace
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evaluate_candidate_v3 as e
from static_test_support import static_temp


def clean():
    return {'cleanupVerified':True, 'finalAbsenceVerified':True, 'rootReaped':True, 'scopeVerified':True, 'scopeAdmitted':True,
            'kernelScope':{'finalAbsenceVerified':True}}


class CandidateLeafLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=static_temp('static-process'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def leaf(self, scope, name='leaf'):
        path=self.root/name;path.mkdir();scope.own(path);return path

    def test_consumed_verified_flat_leaf_reclaimed_without_following_links(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        canary=self.root/'canary';canary.write_bytes(b'untouched')
        (leaf/'output').write_bytes(b'consumed');(leaf/'link').symlink_to(canary)
        scope.call(leaf,lambda: ({},clean()))
        scope.close()
        self.assertFalse(leaf.exists());self.assertEqual(canary.read_bytes(),b'untouched')

    def test_unknown_or_partial_cleanup_retains_leaf(self):
        for field in ('cleanupVerified','finalAbsenceVerified','rootReaped','scopeVerified','scopeAdmitted','kernelScope'):
            scope=e.WorkerLeaves();leaf=self.leaf(scope,field)
            result=clean();result[field]=False
            scope.call(leaf,lambda: ({},result));scope.close()
            self.assertTrue(leaf.exists())

    def test_later_unknown_cannot_be_overwritten_by_success(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        scope.call(leaf,lambda: ({},None));scope.call(leaf,lambda: ({},clean()))
        scope.close();self.assertTrue(leaf.exists())

    def test_exception_unknown_retains_and_primary_preserved(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        error=ValueError('primary')
        def fail(): raise error
        with self.assertRaises(ValueError) as caught:scope.call(leaf,fail)
        scope.close();self.assertIs(caught.exception,error);self.assertTrue(leaf.exists())

    def test_exception_with_verified_cleanup_can_reclaim(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        error=ValueError('consumed');error.bounded_result=clean()
        def fail():raise error
        with self.assertRaises(ValueError):scope.call(leaf,fail)
        scope.close();self.assertFalse(leaf.exists())

    def test_unknown_subtree_and_replaced_leaf_preserved(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope);(leaf/'unexpected').mkdir()
        scope.close();self.assertTrue(leaf.exists())
        scope=e.WorkerLeaves();leaf=self.leaf(scope,'replaced');held=self.root/'held'
        leaf.rename(held);leaf.mkdir();(leaf/'canary').write_bytes(b'keep')
        scope.close();self.assertEqual((leaf/'canary').read_bytes(),b'keep');self.assertTrue(held.exists())

    def test_all_inspection_producers_must_have_verified_cleanup(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        scope.call(leaf,lambda:{'execution':clean(),'sectionsExecution':{}})
        scope.close();self.assertTrue(leaf.exists())

    def runtime_inputs(self, scope):
        link=self.leaf(scope,'link');library=link/'library.so';library.write_bytes(b'owned library')
        scope.call(link,lambda: ({},clean()))  # Successful producer cleanup.
        caller_leaf=self.leaf(scope,'caller');caller=caller_leaf/'caller';caller.write_bytes(b'owned caller')
        scope.call(caller_leaf,lambda: ({},clean()))
        runtime=self.leaf(scope,'runtime')
        command=['/usr/bin/bwrap','--ro-bind',str(caller),'/caller',
                 '--ro-bind',str(library),'/library.so','--chdir','/workspace','/caller']
        return link,library,caller_leaf,runtime,command

    def test_unverified_runtime_retains_all_mounted_inputs_despite_later_verified_run(self):
        scope=e.WorkerLeaves();link,library,caller_leaf,runtime,command=self.runtime_inputs(scope)
        unrelated=self.leaf(scope,'unrelated');token=e._LEAF_SCOPE.set(scope)
        try:
            with patch.object(e,'_run',return_value=({},None)):
                e.run(command,runtime,phase='runtime')
            later=self.leaf(scope,'later-runtime')
            with patch.object(e,'_run',return_value=({},clean())):
                e.run(command,later,phase='runtime')
        finally:e._LEAF_SCOPE.reset(token);scope.close()
        self.assertEqual(library.read_bytes(),b'owned library')
        self.assertTrue(caller_leaf.exists());self.assertTrue(runtime.exists())
        self.assertFalse(later.exists());self.assertFalse(unrelated.exists())

    def test_runtime_exception_preserves_every_mounted_owned_leaf_and_primary(self):
        scope=e.WorkerLeaves();link,library,caller_leaf,runtime,command=self.runtime_inputs(scope)
        error=ValueError('unverified runtime');token=e._LEAF_SCOPE.set(scope)
        try:
            with patch.object(e,'_run',side_effect=error),self.assertRaises(ValueError) as caught:
                e.run(command,runtime,phase='runtime')
            self.assertIs(caught.exception,error)
        finally:e._LEAF_SCOPE.reset(token);scope.close()
        self.assertEqual(library.read_bytes(),b'owned library')
        self.assertTrue(caller_leaf.exists());self.assertTrue(runtime.exists())

    def test_verified_runtime_reclaims_work_and_mounted_owned_leaves(self):
        scope=e.WorkerLeaves();link,library,caller_leaf,runtime,command=self.runtime_inputs(scope)
        token=e._LEAF_SCOPE.set(scope)
        try:
            with patch.object(e,'_run',return_value=({},clean())):
                e.run(command,runtime,phase='runtime')
        finally:e._LEAF_SCOPE.reset(token);scope.close()
        self.assertFalse(link.exists());self.assertFalse(caller_leaf.exists());self.assertFalse(runtime.exists())

    def test_report_hashes_consumed_snapshot_not_reopened_candidate(self):
        candidate=self.root/'candidate.c';original=b'int snapshot;\n';candidate.write_bytes(original)
        for name in ('helper','caller','observations'): (self.root/name).write_bytes(b'fixture')
        visible=self.root/'visible';visible.mkdir()
        def compile_snapshot(source,retain,initial_deadline):
            self.assertIsInstance(source,e.CapturedArtifact)
            self.assertEqual(source.data,original)
            candidate.write_bytes(b'int replaced;\n')
            (self.root/'output/candidate-source.c').chmod(0o600)
            (self.root/'output/candidate-source.c').write_bytes(b'int replaced copy;\n')
            self.assertEqual(source.data,original)
            return {},{}
        summary={'runtimeRequestCount':0,'behaviorStatus':'not-attempted'}
        # The production namespace gate remains active; the repository fixture
        # path includes its required trusted-copy namespace.
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'verify_visible'),patch.object(e,'validated_observations',return_value=[]),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'compile_sequence',side_effect=compile_snapshot),patch.object(e,'summarize',return_value=summary),patch.object(e,'digest',return_value='a'*64),patch.object(e,'validate_exchange'),patch.object(e,'write_json'):
            report=e.evaluate(candidate,self.root/'output',self.root/'helper',self.root/'caller',visible,self.root/'observations')
        self.assertEqual(report['candidateSha256'],hashlib.sha256(original).hexdigest())
        self.assertNotEqual(report['candidateSha256'],hashlib.sha256(candidate.read_bytes()).hexdigest())


class PhaseArtifactContinuity(unittest.TestCase):
    """Authored file/proof vectors only; every worker boundary is mocked."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=static_temp('static-process'))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.now=10.0;self.end=40.0
        self.clock=patch('interface_gate_v3.time.monotonic',side_effect=lambda:self.now)
        self.clock.start();self.addCleanup(self.clock.stop)

    def artifact(self,name='producer.i',data=b'authored original output'):
        path=self.root/name;path.write_bytes(data)
        return path,e.capture_artifact(path,deadline=self.end)

    def process(self,pins,phase='compiler',code=0,stdout=b''):
        from test_process_results import receipt
        target='/synthetic/compiler'
        rows={target:{'device':71,'inode':72,'mode':0o500,'sha256':'d'*64},**pins}
        return receipt(code,stdout=stdout,phase=phase,caller=target,caller_sha='d'*64,input_pins=rows)

    def test_captured_bytes_survive_rename_and_inplace_change_for_every_later_copy(self):
        source,artifact=self.artifact();source.rename(self.root/'original-held')
        source.write_bytes(b'authored replacement')
        (self.root/'original-held').write_bytes(b'changed held inode')
        for label in ('compile.i','probe.i','assertions.i','export.so','runtime.so'):
            copied=e.copy_input(artifact,self.root/label,deadline=self.end)
            self.assertEqual(artifact.data,copied.path.read_bytes())
            self.assertEqual(artifact.sha256,copied.pin()['sha256'])
            self.assertEqual(0o400,copied.pin()['mode'])
        with self.assertRaisesRegex(ValueError,'pathname fallback'):
            e.copy_input(source,self.root/'forbidden',deadline=self.end)
        self.assertFalse((self.root/'forbidden').exists())

    def test_capture_admits_type_and_size_before_read_and_closes_both_fds(self):
        source,_=self.artifact();original_fstat=os.fstat;original_close=os.close
        for mode,size in ((stat.S_IFIFO,1),(stat.S_IFREG,e.load_profile()['bounds']['fileSizeBytes']+1)):
            def metadata(fd):
                row=original_fstat(fd)
                if stat.S_ISREG(row.st_mode):
                    return SimpleNamespace(st_dev=row.st_dev,st_ino=row.st_ino,st_mode=mode,st_size=size,
                                           st_mtime_ns=row.st_mtime_ns,st_ctime_ns=row.st_ctime_ns)
                return row
            with self.subTest(mode=mode),patch.object(e,'_handoff_parent',return_value=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)),patch.object(e.os,'fstat',side_effect=metadata),patch.object(e.os,'read') as read,patch.object(e.os,'close',side_effect=original_close) as close:
                with self.assertRaisesRegex(ValueError,'bounded regular-file'):
                    e.capture_artifact(source,deadline=self.end)
                read.assert_not_called();self.assertEqual(2,close.call_count)

    def test_capture_refuses_mutation_and_expiry_during_read_without_snapshot(self):
        source,_=self.artifact();original_read=os.read
        for change in ('inplace','late','truncated'):
            source.write_bytes(b'authored original output');self.now=10.0
            def read(fd,size):
                if change=='inplace':source.write_bytes(b'X'*len(b'authored original output'))
                if change=='late':self.now=self.end
                return b'' if change=='truncated' else original_read(fd,size)
            with self.subTest(change=change),patch.object(e.os,'read',side_effect=read):
                with self.assertRaises((ValueError,TimeoutError)):
                    e.capture_artifact(source,deadline=self.end)

    def test_empty_output_and_partial_copy_writes_keep_existing_policy(self):
        source,empty=self.artifact('empty.i',b'')
        self.assertEqual(b'',e.copy_input(empty,self.root/'empty-copy',deadline=self.end).path.read_bytes())
        _,artifact=self.artifact();original_write=os.write
        def partial(fd,data):return original_write(fd,data[:2])
        with patch.object(e.os,'write',side_effect=partial):
            copied=e.copy_input(artifact,self.root/'partial',deadline=self.end)
        self.assertEqual(artifact.data,copied.path.read_bytes())
        with patch.object(e.os,'write',return_value=0):
            with self.assertRaisesRegex(ValueError,'copy incomplete'):
                e.copy_input(artifact,self.root/'zero-write',deadline=self.end)

    def test_capture_and_copy_close_failure_never_return_usable_value(self):
        source,artifact=self.artifact();original_close=os.close
        def failed_close(fd):
            original_close(fd)
            raise OSError('authored close uncertainty')
        for action in (lambda:e.capture_artifact(source,deadline=self.end),
                       lambda:e.copy_input(artifact,self.root/'close-copy',deadline=self.end)):
            parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            with patch.object(e,'_handoff_parent',return_value=parent),patch.object(e.os,'close',side_effect=failed_close) as close:
                with self.assertRaises(OSError):action()
                self.assertEqual(2,close.call_count)

    def test_copy_refuses_symlink_and_existing_destination_without_touching_target(self):
        source,artifact=self.artifact();destination=self.root/'alias';destination.symlink_to(source)
        with self.assertRaises(OSError):e.copy_input(artifact,destination,deadline=self.end)
        self.assertEqual(artifact.data,source.read_bytes())
        self.assertTrue(destination.is_symlink())

    def test_compile_chain_captures_once_and_uses_original_after_each_output_swap(self):
        produced={};calls=[];capture=e.capture_artifact;copy=e.copy_input
        phases=[('preprocess','candidate.c','candidate.i',b'authored preprocessed'),
                ('compile','candidate.i','candidate.o',b'authored object'),
                ('link','candidate.o','libcandidate.so',b'authored library')]
        def leaf(label):
            path=self.root/label;path.mkdir();return path
        def copied(artifact,destination,**kwargs):
            for path in produced.values():
                path.write_bytes(b'changed original producer path')
            return copy(artifact,destination,**kwargs)
        def worker(argv,work,timeout,phase,**kwargs):
            index=len(calls);label,input_name,output_name,data=phases[index]
            expected=b'authored source' if index==0 else phases[index-1][3]
            self.assertEqual(expected,(work/input_name).read_bytes())
            self.assertEqual(e.load_profile()['commands'][label],argv[-len(e.load_profile()['commands'][label]):])
            pins={str(work/input_name):e.CopiedInput(work/input_name,e._file_version((work/input_name).stat()),hashlib.sha256(expected).hexdigest()).pin()}
            produced[label]=work/output_name;produced[label].write_bytes(data);calls.append(label)
            return {'status':'passed'},self.process(pins)
        with patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'copy_input',side_effect=copied),patch.object(e,'_run',side_effect=worker),patch.object(e,'capture_artifact',wraps=capture) as snapshots:
            statuses,artifacts=e.compile_sequence(e.CapturedArtifact(b'authored source'),initial_deadline=self.end)
        self.assertEqual(['preprocess','compile','link'],calls)
        self.assertEqual(3,snapshots.call_count)
        self.assertTrue(all(row['status']=='passed' for row in statuses.values()))
        self.assertEqual([row[3] for row in phases],[artifacts[row[0]].data for row in phases])
        self.assertFalse(artifacts['link'].evidence()['producerOriginQualified'])
        self.assertFalse(artifacts['link'].evidence()['ordinaryMountAbaQualified'])

    def test_changed_copy_or_missing_consumer_pin_is_unknown_and_never_rebaseline(self):
        _,artifact=self.artifact();copied=e.copy_input(artifact,self.root/'input.i',deadline=self.end)
        pins=e._input_pins([copied])
        for change in ('missing','different-inode','wrong-profile','wrong-phase','incomplete','bad-proof'):
            raw=self.process(pins)
            if change=='missing':
                # A valid protected result for another file cannot stand in for this input.
                raw=self.process({})
            elif change=='different-inode':
                wrong=deepcopy(pins);wrong[str(copied.path)]['inode']+=1;raw=self.process(wrong)
            elif change=='wrong-profile':raw['bounds']['profileSha256']='f'*64
            elif change=='wrong-phase':raw=self.process(pins,phase='probe')
            elif change=='incomplete':raw['captureComplete']=False
            else:raw['workerProofRaw']=b'authored invalid proof'
            with self.subTest(change=change),patch.object(e,'_run',return_value=({'status':'passed'},raw)):
                status,result=e.run(['/usr/bin/bwrap'],self.root,deadline=self.end,expected_inputs=pins)
            self.assertEqual('unknown',status['status']);self.assertFalse(e.process_observation(result)['completed'])
        copied.path.chmod(0o600);copied.path.write_bytes(b'changed materialization')
        with patch.object(e,'_run') as worker:
            status,result=e.run(['/usr/bin/bwrap'],self.root,deadline=self.end,expected_inputs=pins)
        worker.assert_not_called();self.assertEqual('unknown',status['status']);self.assertIsNone(result)

    def test_metadata_and_worker_share_absolute_end_and_late_zero_is_unknown(self):
        _,artifact=self.artifact();copied=e.copy_input(artifact,self.root/'deadline.i',deadline=self.end)
        pins=e._input_pins([copied]);revalidate=e.revalidate_handoff;allowances=[]
        def setup(expected,end):
            revalidate(expected,end);self.now=39.0
        def worker(argv,work,timeout,phase,**kwargs):
            self.assertEqual(self.end,kwargs['phase_deadline'])
            allowances.append(timeout);self.now=40.0
            return {'status':'passed'},self.process(pins)
        with patch.object(e,'revalidate_handoff',side_effect=setup),patch.object(e,'_run',side_effect=worker):
            status,result=e.run(['/usr/bin/bwrap'],self.root,deadline=self.end,expected_inputs=pins)
        self.assertEqual([1.0],allowances);self.assertEqual('unknown',status['status'])
        self.assertFalse(e.process_observation(result)['completed'])

    def test_bounded_runner_forwards_finite_absolute_end_and_preserves_default_contract(self):
        import bounded_runtime as runtime
        with patch.object(runtime,'_run_scoped',return_value={}) as scoped:
            runtime.bounded_run(['NOT_EXECUTED'],self.root,{},managed_scope=True,phase='compiler',phase_deadline=self.end)
            self.assertEqual(self.end,scoped.call_args.kwargs['phase_deadline'])
            runtime.bounded_run(['NOT_EXECUTED'],self.root,{},managed_scope=True,phase='compiler')
            self.assertNotIn('phase_deadline',scoped.call_args.kwargs)
            for endpoint in (True,float('nan'),float('inf'),'40',10.0):
                scoped.reset_mock()
                with self.assertRaises((ValueError,TimeoutError)):
                    runtime.bounded_run(['NOT_EXECUTED'],self.root,{},managed_scope=True,phase='compiler',phase_deadline=endpoint)
                scoped.assert_not_called()

    def test_supervisor_uses_original_absolute_end_and_refuses_late_prelaunch_setup(self):
        import bounded_runtime as runtime
        seen=[]
        def prepared(*args,**kwargs):
            seen.append(kwargs['deadline']);self.now=15.0
            return {'proofBinding':{},'pins':{},'argv':['NOT_EXECUTED']}
        bounds=runtime.execution_bounds(managed_scope=True,phase='compiler')
        with patch.object(runtime,'_work_directory',return_value=self.root),patch.object(runtime,'_worker_environment'),patch.object(runtime,'_create_worker_receipt',return_value={'directory':self.root,'fd':None}),patch.object(runtime,'_prepare_launch',side_effect=prepared),patch.object(runtime,'_finish_worker_proof') as proof,patch.object(runtime,'_reclaim_worker_receipt',return_value={'status':'not-created'}),patch.object(runtime.subprocess,'Popen',side_effect=AssertionError('native launch forbidden')) as launch:
            with self.assertRaises(TimeoutError) as caught:
                runtime._run_scoped(['NOT_EXECUTED'],self.root,{},b'',bounds,provisioning=False,phase_deadline=15.0)
        self.assertEqual([15.0],seen);launch.assert_not_called()
        self.assertEqual(15.0,proof.call_args.kwargs['deadline'])
        self.assertEqual(5.0,caught.exception.bounded_result['bounds']['wallSeconds'])
        self.assertTrue(caught.exception.bounded_result['timedOut'])
        self.assertIsNone(caught.exception.bounded_result['exitCode'])

    def test_compile_missing_output_stops_chain_as_unknown_not_candidate_failure(self):
        def leaf(label):path=self.root/label;path.mkdir();return path
        with patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'run',return_value=({'status':'passed','execution':{'authored':'retained producer record'}},None)) as worker:
            statuses,artifacts=e.compile_sequence(e.CapturedArtifact(b'authored source'),initial_deadline=self.end)
        self.assertEqual('unknown',statuses['preprocess']['status']);self.assertEqual({},artifacts)
        self.assertEqual({'authored':'retained producer record'},statuses['preprocess']['execution'])
        self.assertEqual(1,worker.call_count)

    def test_probe_binds_source_helper_and_refuses_independently_substituted_launch_pin(self):
        import interface_gate_v3 as gate
        from test_identity_graph import graph
        from test_process_results import receipt
        _,artifact=self.artifact();source=e.copy_input(artifact,self.root/'probe.i',deadline=self.end)
        helper=self.root/'helper';helper.write_bytes(b'authored inert helper')
        helper_pin=e.CopiedInput(helper,e._file_version(helper.stat()),hashlib.sha256(helper.read_bytes()).hexdigest()).pin()
        expected=e._input_pins([source]);sha=helper_pin['sha256'];commands=[]
        for wrong in (False,True):
            pins={**expected,str(helper):helper_pin}
            if wrong:pins[str(source.path)]={**pins[str(source.path)],'sha256':'f'*64}
            raw=receipt(stdout=json.dumps(graph()).encode(),phase='probe',caller=str(helper),caller_sha=sha,input_pins=pins)
            with patch.object(gate,'bounded_run',return_value=raw) as worker:
                if wrong:
                    with self.assertRaisesRegex(ValueError,'launch pins differ'):
                        gate.probe(source.path,helper,self.root,{},deadline=self.end,expected_inputs=expected)
                else:
                    value=gate.probe(source.path,helper,self.root,{},deadline=self.end,expected_inputs=expected)
                    self.assertEqual(artifact.sha256,value['inputBindings']['sourceSha256'])
                    commands.append(worker.call_args.args[0])
        self.assertIn(['--ro-bind',str(source.path),'/work/probe.i'],[commands[0][n:n+3] for n in range(len(commands[0]))])

    def test_export_both_inspections_share_same_copy_and_deadline(self):
        import interface_gate_v3 as gate
        _,artifact=self.artifact('library.so');library=e.copy_input(artifact,self.root/'inspected.so',deadline=self.end)
        expected=e._input_pins([library]);calls=[]
        symbols='\n'.join('1: 00000000 8 '+('OBJECT' if name=='acp_state' else 'FUNC')+' GLOBAL DEFAULT 1 '+name for name in sorted(gate.REQUIRED)).encode()
        sections=b'[ 1] .data PROGBITS 00000000 000040 000008 00 WA 0 0 8\n'
        def worker(argv,work,environment,**kwargs):
            index=len(calls);calls.append(kwargs['timeout'])
            raw=self.process(expected,phase='elf-inspection',stdout=symbols if index==0 else sections)
            self.now+=1
            return raw
        with patch.object(gate,'contained_command',return_value=['NOT_EXECUTED']),patch.object(gate,'bounded_run',side_effect=worker):
            result=gate.export_inventory(library.path,8,self.root,{},deadline=self.end,expected_inputs=expected)
        self.assertEqual('passed',result['status']);self.assertEqual([10,9],calls)
        # Near the original end, the second subprocess gets only the remaining interval.
        self.now=19.0;self.end=20.0;calls.clear()
        with patch.object(gate,'contained_command',return_value=['NOT_EXECUTED']),patch.object(gate,'bounded_run',side_effect=worker) as launched:
            result=gate.export_inventory(library.path,8,self.root,{},deadline=self.end,expected_inputs=expected)
        self.assertEqual('unknown',result['status']);self.assertEqual(1,launched.call_count)
        self.assertEqual([1.0],calls)

    def test_all_evaluator_consumers_share_captured_candidate_expected_and_library_bytes(self):
        import interface_gate_v3 as gate
        from test_identity_graph import graph
        from test_process_results import receipt
        candidate=self.root/'candidate.c';candidate.write_bytes(b'authored candidate source')
        helper=self.root/'helper';helper.write_bytes(b'authored inert helper')
        caller=self.root/'caller';caller.write_bytes(b'authored inert caller')
        visible=self.root/'visible';visible.mkdir()
        observations_path=self.root/'observations.json';observations_path.write_bytes(b'authored placeholder')
        private=self.root/'private';private.mkdir()
        originals={'original.c':b'authored reference source','original.h':b'authored reference header'}
        for name,data in originals.items():(private/name).write_bytes(data)
        contracts=self.root/'contracts';contracts.mkdir()
        (contracts/'candidate-build-profile.json').write_bytes((e.BASE/'contracts/candidate-build-profile.json').read_bytes())
        (self.root/'worker_exec_proof.py').write_bytes((e.BASE/'worker_exec_proof.py').read_bytes())
        def pin(path):return e.CopiedInput(path,e._file_version(path.stat()),hashlib.sha256(path.read_bytes()).hexdigest()).pin()
        caller_pin=pin(caller);observations=[]
        for i,family in enumerate(e.SCENARIO_FAMILIES):
            raw=receipt(caller=str(caller),caller_sha=caller_pin['sha256'],input_pins={str(caller):caller_pin})
            observations.append({'id':i,'family':family,'process':e.process_observation(raw)})
        produced=[];leaf_count=[];runs=[];probes=[];inspections=[];copy=e.copy_input
        candidate_pre=b'authored preprocessed candidate';reference_pre=b'authored preprocessed reference'
        linked=b'authored linked library'
        def leaf(label):
            path=self.root/(label+'-'+str(len(leaf_count)));path.mkdir();leaf_count.append(label)
            scope=e._LEAF_SCOPE.get()
            if scope is not None:scope.own(path)
            return path
        def copied(artifact,destination,**kwargs):
            # Mutating every original output after capture must not change any consumer.
            for path in produced:path.write_bytes(b'authored changed original output')
            return copy(artifact,destination,**kwargs)
        def mounted(argv):
            paths=[Path(argv[i+1]) for i,arg in enumerate(argv[:-1]) if arg=='--ro-bind']
            return {str(path):pin(path) for path in paths if path.is_relative_to(self.root) and path.is_file()}
        def compiler(argv,work,timeout,phase,**kwargs):
            pins=mounted(argv);runs.append(phase)
            if phase=='runtime':
                self.assertEqual(linked,Path(kwargs['runtime_library']['path']).read_bytes())
                self.assertEqual(hashlib.sha256(linked).hexdigest(),kwargs['runtime_library']['sha256'])
                return {'status':'passed'},receipt(caller=str(caller),caller_sha=caller_pin['sha256'],input_pins=pins)
            if '-E' in argv:
                trusted=(work/'original.c').exists()
                if trusted:
                    for name,data in originals.items():self.assertEqual(data,(work/name).read_bytes())
                else:self.assertEqual(b'authored candidate source',(work/'candidate.c').read_bytes())
                output=work/('expected.i' if trusted else 'candidate.i')
                output.write_bytes(reference_pre if trusted else candidate_pre);produced.append(output)
            elif '-fsyntax-only' in argv:
                trusted=(work/'expected.i').exists()
                self.assertEqual(reference_pre if trusted else candidate_pre,(work/('expected.i' if trusted else 'candidate.i')).read_bytes())
            elif '-c' in argv:
                self.assertEqual(candidate_pre,(work/'candidate.i').read_bytes())
                output=work/'candidate.o';output.write_bytes(b'authored object');produced.append(output)
            else:
                self.assertEqual(b'authored object',(work/'candidate.o').read_bytes())
                output=work/'libcandidate.so';output.write_bytes(linked);produced.append(output)
            return {'status':'passed'},self.process(pins)
        symbols='\n'.join('1: 00000000 8 '+('OBJECT' if name=='acp_state' else 'FUNC')+' GLOBAL DEFAULT 1 '+name for name in sorted(gate.REQUIRED)).encode()
        sections=b'[ 1] .data PROGBITS 00000000 000040 000008 00 WA 0 0 8\n'
        def inspection(argv,work,environment,**kwargs):
            pins=mounted(argv)
            if kwargs['phase']=='probe':
                trusted=(work/'original.c').exists();probes.append(trusted)
                self.assertEqual(originals['original.c'] if trusted else candidate_pre,(work/('original.c' if trusted else 'candidate.i')).read_bytes())
                # The later expected preprocessing must not recapture this changed source/header.
                if trusted:
                    for name in originals:(private/name).write_bytes(b'authored changed private pathname')
                return receipt(stdout=json.dumps(graph()).encode(),phase='probe',caller=str(helper),caller_sha=pin(helper)['sha256'],input_pins=pins)
            self.assertEqual(linked,(work/'libcandidate.so').read_bytes());inspections.append(1)
            return self.process(pins,phase='elf-inspection',stdout=symbols if len(inspections)==1 else sections)
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'verify_visible'),patch.object(e,'validated_observations',return_value=observations),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'copy_input',side_effect=copied),patch.object(e,'_run',side_effect=compiler),patch.object(gate,'bounded_run',side_effect=inspection),patch.object(e,'validate_exchange'):
            report=e.evaluate(candidate,self.root/'output',helper,caller,visible,observations_path)
        diagnostic=json.dumps({
            'phases':{name:{'status':row['status'],'reason':str(row.get('reason',''))[:300]}
                      for name,row in report['phases'].items()},
            'mockedRuns':runs,'ownedLeafLabels':leaf_count,
            'mockedProbeKinds':probes,'mockedInspectionCount':len(inspections),
            'runtimeRequestCount':report.get('runtimeRequestCount'),
        },sort_keys=True)
        self.assertEqual([True,False],probes,diagnostic);self.assertEqual(2,len(inspections))
        self.assertEqual(6,runs.count('compiler'));self.assertEqual(24,runs.count('runtime'))
        self.assertEqual(24,report['matchedScenarioProcessCount']);self.assertEqual(0,report['unknownScenarioProcessCount'])
        self.assertEqual(hashlib.sha256(b'authored candidate source').hexdigest(),report['candidateSha256'])
        self.assertEqual(hashlib.sha256(linked).hexdigest(),report['runtimeInputs']['library']['sha256'])
        for key in ('productionFactoryQualified','productionProviderQualified','productionFilesystemQualified'):
            self.assertFalse(report[key])
        self.assertIsNone(report['apiEntryCount']);self.assertIsNone(report['callbackCount'])

    def test_export_substituted_second_execution_pin_cannot_credit_library(self):
        import interface_gate_v3 as gate
        _,artifact=self.artifact('library.so');library=e.copy_input(artifact,self.root/'inspected.so',deadline=self.end)
        expected=e._input_pins([library]);calls=[]
        def worker(*args,**kwargs):
            pins=deepcopy(expected)
            if calls:pins[str(library.path)]['sha256']='e'*64
            calls.append(1)
            return self.process(pins,phase='elf-inspection')
        with patch.object(gate,'contained_command',return_value=['NOT_EXECUTED']),patch.object(gate,'bounded_run',side_effect=worker):
            value=gate.export_inventory(library.path,8,self.root,{},deadline=self.end,expected_inputs=expected)
        self.assertEqual('unknown',value['status']);self.assertEqual(2,len(calls))
        self.assertIn('execution',value);self.assertIn('sectionsExecution',value)


    def export_vectors(self):
        import interface_gate_v3 as gate
        symbols='\n'.join('1: 00000000 8 '+('OBJECT' if name=='acp_state' else 'FUNC')+' GLOBAL DEFAULT 1 '+name for name in sorted(gate.REQUIRED)).encode()
        sections=b'[ 1] .data PROGBITS 00000000 000040 000008 00 WA 0 0 8\n'
        return symbols,sections

    def test_export_exception_retains_original_partial_second_and_first_receipts(self):
        import interface_gate_v3 as gate
        _,artifact=self.artifact('library.so');library=e.copy_input(artifact,self.root/'inspected.so',deadline=self.end)
        expected=e._input_pins([library]);symbols,_=self.export_vectors()
        for error_type in (TimeoutError,RuntimeError):
            first=self.process(expected,phase='elf-inspection',stdout=symbols)
            partial=self.process(expected,phase='elf-inspection',stdout=b'authored partial sections')
            partial.update(stderr=b'authored partial diagnostic',captureComplete=False,infrastructureFailure=True,cleanupVerified=False,finalAbsenceVerified=False,exitCode=None)
            partial['kernelScope']['finalAbsenceVerified']=False
            original_first=deepcopy(first);original_partial=deepcopy(partial)
            failure=error_type('authored partial second-call failure');failure.bounded_result=partial
            scope=e.WorkerLeaves();scope.own(self.root);token=e._LEAF_SCOPE.set(scope)
            try:
                with patch.object(gate,'contained_command',return_value=['NOT_EXECUTED']),patch.object(gate,'bounded_run',side_effect=[first,failure]) as worker:
                    value=e._leaf_call(self.root,lambda:gate.export_inventory(library.path,8,self.root,{},deadline=self.end,expected_inputs=expected))
                self.assertEqual(2,worker.call_count)
            finally:
                e._LEAF_SCOPE.reset(token);scope.close()
            self.assertTrue(self.root.exists())  # Partial cleanup cannot certify leaf reclamation.
            self.assertEqual('unknown',value['status']);self.assertFalse(value['accepted'])
            self.assertEqual(gate.public_result(original_first),value['execution'])
            self.assertEqual(gate.public_result(original_partial),value['sectionsExecution'])
            self.assertEqual(original_first,first);self.assertEqual(original_partial,partial)
            self.assertFalse(value['sectionsExecution']['captureComplete'])
            self.assertIsNone(value['sectionsExecution']['exitCode'])

    def test_export_final_parse_expiry_retains_both_original_complete_receipts(self):
        import interface_gate_v3 as gate
        _,artifact=self.artifact('library.so');library=e.copy_input(artifact,self.root/'inspected.so',deadline=self.end)
        expected=e._input_pins([library]);symbols,sections=self.export_vectors()
        first=self.process(expected,phase='elf-inspection',stdout=symbols)
        second=self.process(expected,phase='elf-inspection',stdout=sections)
        originals=deepcopy((first,second));names=tuple(gate.REQUIRED);test=self;self.end=20.0
        class ExpireAfterBothOutputParsers:
            def __iter__(self):
                test.now=test.end
                return iter(names)
        with patch.object(gate,'contained_command',return_value=['NOT_EXECUTED']),patch.object(gate,'bounded_run',side_effect=[first,second]) as worker,patch.object(gate,'REQUIRED',ExpireAfterBothOutputParsers()):
            value=gate.export_inventory(library.path,8,self.root,{},deadline=self.end,expected_inputs=expected)
        self.assertEqual(2,worker.call_count)
        self.assertEqual('unknown',value['status']);self.assertFalse(value['accepted'])
        self.assertIn('TimeoutError',value['reason'])
        self.assertEqual(gate.public_result(originals[0]),value['execution'])
        self.assertEqual(gate.public_result(originals[1]),value['sectionsExecution'])
        self.assertEqual(originals,(first,second))
        self.assertEqual(0,value['execution']['exitCode']);self.assertEqual(0,value['sectionsExecution']['exitCode'])

    def test_export_malformed_outputs_retain_both_available_original_receipts(self):
        import interface_gate_v3 as gate
        _,artifact=self.artifact('library.so');library=e.copy_input(artifact,self.root/'inspected.so',deadline=self.end)
        expected=e._input_pins([library]);symbols,sections=self.export_vectors()
        bad_size=symbols.replace(b' 8 OBJECT ',b' not-a-number OBJECT ')
        for out,section in ((symbols,b'\xff'),(bad_size,sections)):
            first=self.process(expected,phase='elf-inspection',stdout=out)
            second=self.process(expected,phase='elf-inspection',stdout=section)
            originals=deepcopy((first,second))
            with patch.object(gate,'contained_command',return_value=['NOT_EXECUTED']),patch.object(gate,'bounded_run',side_effect=[first,second]) as worker:
                value=gate.export_inventory(library.path,8,self.root,{},deadline=self.end,expected_inputs=expected)
            self.assertEqual(2,worker.call_count)
            self.assertEqual('unknown',value['status']);self.assertFalse(value['accepted'])
            self.assertEqual(gate.public_result(originals[0]),value['execution'])
            self.assertEqual(gate.public_result(originals[1]),value['sectionsExecution'])
            self.assertEqual(originals,(first,second))


if __name__=='__main__':unittest.main()
