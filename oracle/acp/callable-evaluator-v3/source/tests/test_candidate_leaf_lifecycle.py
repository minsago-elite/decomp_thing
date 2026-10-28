"""Pure snapshot/leaf controls; legacy reclaim test IDs now require retention.

Worker absence facts remain independently asserted; they cannot authorize deleting
mutable names. No processes are executed by these controls.
"""
import ast
import io
import hashlib
import json
import os
import stat
from types import SimpleNamespace
from copy import deepcopy
from contextlib import contextmanager, ExitStack
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evaluate_candidate_v3 as e
import build_contract as contract
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

    @contextmanager
    def runner_refusal(self, leaf, *, attempted=False):
        """Actual controller refusal paths; no mocked cleanup or completion policy."""
        import bounded_runtime as runtime
        bounds=runtime.execution_bounds(managed_scope=True,phase='compiler')
        primary=OSError('authored ambiguous Popen failure') if attempted else ValueError('authored preparation refusal')
        receipt={'directory':self.root/'authored-receipt','fd':None}
        launch={'argv':['NOT_EXECUTED'],'proofBinding':{},'pins':{}}
        forbidden=AssertionError('prelaunch control forbids process, policy and descriptor effects')
        denied=[]
        with ExitStack() as effects:
            effects.enter_context(patch.object(runtime,'_work_directory',return_value=leaf))
            effects.enter_context(patch.object(runtime,'_worker_environment'))
            effects.enter_context(patch.object(runtime,'_create_worker_receipt',return_value=receipt))
            effects.enter_context(patch.object(runtime,'_prepare_launch',
                return_value=launch,side_effect=None if attempted else primary))
            popen=effects.enter_context(patch.object(runtime.subprocess,'Popen',
                side_effect=primary if attempted else forbidden))
            effects.enter_context(patch.object(runtime.time,'monotonic',return_value=1.0))
            effects.enter_context(patch.object(runtime.os,'getuid',return_value=1000))
            for name in ('open','close','fstat','stat','lstat','pread','read','write','pidfd_open'):
                denied.append(effects.enter_context(patch.object(runtime.os,name,side_effect=forbidden)))
            for name in ('process_identity','_admit_scope','_kill_owned_scope','_kill_launcher',
                         'scope_processes','owned_processes','process_limits'):
                denied.append(effects.enter_context(patch.object(runtime,name,side_effect=forbidden)))
            denied.append(effects.enter_context(patch.object(runtime.selectors,'DefaultSelector',side_effect=forbidden)))
            try:
                yield (lambda: runtime._run_scoped(['NOT_EXECUTED'],leaf,{},b'',bounds,provisioning=False)),primary,popen
            finally:
                for effect in denied:effect.assert_not_called()

    def test_actual_prelaunch_refusal_reclaims_owned_leaf_without_completion_credit(self):
        import bounded_runtime as runtime
        for returned in (False,True):
            scope=e.WorkerLeaves();leaf=self.leaf(scope,'prelaunch-'+str(returned))
            (leaf/'copied-input').write_bytes(b'consumed controller input')
            with self.runner_refusal(leaf) as (operation,primary,popen):
                if returned:
                    def refused():
                        try:operation()
                        except ValueError as error:
                            self.assertIs(primary,error)
                            return {'status':'unknown'},error.bounded_result
                    value=scope.call(leaf,refused)
                    self.assertEqual('unknown',value[0]['status'])
                else:
                    with self.assertRaises(ValueError) as caught:scope.call(leaf,operation)
                    self.assertIs(primary,caught.exception)
                popen.assert_not_called()
            result=primary.bounded_result
            self.assertTrue(result['cleanupVerified']);self.assertTrue(result['finalAbsenceVerified'])
            self.assertFalse(result['launcherCreated']);self.assertFalse(result['rootReaped'])
            self.assertIsNone(result['rootPid']);self.assertIsNone(result['kernelScope'])
            self.assertFalse(runtime.worker_execution_complete(result))
            self.assertEqual('retained',result['_receiptCleanup']['status'])
            self.assertTrue(scope.leaves[leaf]['safe'])
            scope.close();self.assertTrue(leaf.exists())
            self.assertEqual(b'consumed controller input',(leaf/'copied-input').read_bytes())

    def test_actual_popen_attempt_without_handle_retains_leaf_and_primary(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope,'attempted-no-handle')
        with self.runner_refusal(leaf,attempted=True) as (operation,primary,popen):
            with self.assertRaises(OSError) as caught:scope.call(leaf,operation)
            self.assertIs(primary,caught.exception);popen.assert_called_once()
        result=primary.bounded_result
        self.assertFalse(result['launcherCreated']);self.assertIsNone(result['rootPid'])
        self.assertFalse(result['cleanupVerified']);self.assertFalse(result['finalAbsenceVerified'])
        self.assertFalse(e._cleanup_proven(result))
        scope.close();self.assertTrue(leaf.exists())

    def test_prelaunch_cleanup_requires_every_explicit_exact_controller_fact(self):
        with self.runner_refusal(self.root) as (operation,primary,popen):
            with self.assertRaises(ValueError):operation()
            popen.assert_not_called()
        original=primary.bounded_result;self.assertTrue(e._cleanup_proven(original))
        facts=('cleanupVerified','finalAbsenceVerified','launcherCreated','launcherPidIdentityVerified',
               'scopeVerified','scopeAdmitted','waitComplete','rootReaped','workerExecVerified',
               'workerTerminationVerified','rootPid','kernelScope')
        vector=0
        for field in facts:
            for replacement in ('missing',False,True,0,1,None,{}):
                if replacement!='missing' and type(replacement) is type(original[field]) and replacement==original[field]:continue
                with self.subTest(field=field,replacement=replacement):
                    result=deepcopy(original)
                    if replacement=='missing':del result[field]
                    else:result[field]=replacement
                    scope=e.WorkerLeaves();leaf=self.leaf(scope,'bad-fact-'+str(vector));vector+=1
                    self.assertFalse(e._cleanup_proven(result))
                    scope.call(leaf,lambda: ({},result));self.assertFalse(scope.leaves[leaf]['safe'])
                    scope.close();self.assertTrue(leaf.exists())
        for result in (None,{},False,0):
            self.assertFalse(e._cleanup_proven(result))

    def test_prelaunch_cleanup_preserves_sticky_peers_and_mixed_inspection_refusal(self):
        for unsafe in (False,True):
            scope=e.WorkerLeaves();peer=self.leaf(scope,'peer-'+str(unsafe));library=peer/'library.so'
            library.write_bytes(b'owned mounted input');work=self.leaf(scope,'work-'+str(unsafe))
            if unsafe:scope.call(peer,lambda: ({},None))
            with self.runner_refusal(work) as (operation,primary,popen):
                with self.assertRaises(ValueError):scope.call(work,operation,mounted=(library,))
                popen.assert_not_called()
            self.assertTrue(scope.leaves[work]['safe'])
            self.assertEqual(not unsafe,scope.leaves[peer]['safe'])
            scope.close();self.assertTrue(work.exists());self.assertTrue(peer.exists())
            self.assertEqual(b'owned mounted input',library.read_bytes())
        with self.runner_refusal(self.root) as (operation,primary,popen):
            with self.assertRaises(ValueError):operation()
            popen.assert_not_called()
        for index,rows in enumerate(((primary.bounded_result,{}),({},primary.bounded_result),
                                     (clean(),primary.bounded_result))):
            scope=e.WorkerLeaves();leaf=self.leaf(scope,'inspection-'+str(index))
            scope.call(leaf,lambda: {'execution':rows[0],'sectionsExecution':rows[1]})
            self.assertEqual(index==2,scope.leaves[leaf]['safe'])
            scope.close();self.assertTrue(leaf.exists())
        scope=e.WorkerLeaves();leaf=self.leaf(scope,'sticky-work')
        scope.call(leaf,lambda: ({},None))
        with self.runner_refusal(leaf) as (operation,primary,popen):
            with self.assertRaises(ValueError):scope.call(leaf,operation)
            popen.assert_not_called()
        scope.close();self.assertTrue(leaf.exists())

    def test_prelaunch_cleanup_retains_replacements_and_unknown_subtrees(self):
        for replaced in (False,True):
            scope=e.WorkerLeaves();leaf=self.leaf(scope,'protected-prelaunch-'+str(replaced))
            with self.runner_refusal(leaf) as (operation,primary,popen):
                with self.assertRaises(ValueError):scope.call(leaf,operation)
                popen.assert_not_called()
            if replaced:
                held=self.root/'held-prelaunch';leaf.rename(held);leaf.mkdir()
                (leaf/'canary').write_bytes(b'foreign replacement')
            else:(leaf/'unexpected').mkdir()
            scope.close();self.assertTrue(leaf.exists())
            if replaced:
                self.assertTrue(held.exists());self.assertEqual(b'foreign replacement',(leaf/'canary').read_bytes())
            else:self.assertTrue((leaf/'unexpected').is_dir())

    def test_consumed_verified_flat_leaf_reclaimed_without_following_links(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        canary=self.root/'canary';canary.write_bytes(b'untouched')
        (leaf/'output').write_bytes(b'consumed');(leaf/'link').symlink_to(canary)
        scope.call(leaf,lambda: ({},clean()))
        scope.close()
        self.assertTrue(scope.leaves[leaf]['safe']);self.assertTrue(leaf.exists())
        self.assertEqual(b'consumed',(leaf/'output').read_bytes());self.assertTrue((leaf/'link').is_symlink())
        self.assertEqual(canary.read_bytes(),b'untouched')

    def test_unknown_or_partial_cleanup_retains_leaf(self):
        for field in ('cleanupVerified','finalAbsenceVerified','rootReaped','scopeVerified','scopeAdmitted','kernelScope'):
            scope=e.WorkerLeaves();leaf=self.leaf(scope,field)
            result=clean();result[field]=False
            scope.call(leaf,lambda: ({},result));self.assertFalse(scope.leaves[leaf]['safe'])
            scope.close();self.assertTrue(leaf.exists())

    def test_later_unknown_cannot_be_overwritten_by_success(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        scope.call(leaf,lambda: ({},None));scope.call(leaf,lambda: ({},clean()))
        self.assertFalse(scope.leaves[leaf]['safe'])
        scope.close();self.assertTrue(leaf.exists())

    def test_exception_unknown_retains_and_primary_preserved(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        error=ValueError('primary')
        def fail(): raise error
        with self.assertRaises(ValueError) as caught:scope.call(leaf,fail)
        self.assertFalse(scope.leaves[leaf]['safe'])
        scope.close();self.assertIs(caught.exception,error);self.assertTrue(leaf.exists())

    def test_exception_with_verified_cleanup_can_reclaim(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        error=ValueError('consumed');error.bounded_result=clean()
        def fail():raise error
        with self.assertRaises(ValueError):scope.call(leaf,fail)
        self.assertTrue(scope.leaves[leaf]['safe'])
        scope.close();self.assertTrue(leaf.exists())

    def test_unknown_subtree_and_replaced_leaf_preserved(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope);(leaf/'unexpected').mkdir()
        scope.close();self.assertTrue(leaf.exists())
        scope=e.WorkerLeaves();leaf=self.leaf(scope,'replaced');held=self.root/'held'
        leaf.rename(held);leaf.mkdir();(leaf/'canary').write_bytes(b'keep')
        scope.close();self.assertEqual((leaf/'canary').read_bytes(),b'keep');self.assertTrue(held.exists())

    def test_all_inspection_producers_must_have_verified_cleanup(self):
        scope=e.WorkerLeaves();leaf=self.leaf(scope)
        scope.call(leaf,lambda:{'execution':clean(),'sectionsExecution':{}})
        self.assertFalse(scope.leaves[leaf]['safe'])
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
        self.assertFalse(scope.leaves[runtime]['safe']);self.assertFalse(scope.leaves[link]['safe'])
        self.assertFalse(scope.leaves[caller_leaf]['safe'])
        self.assertTrue(scope.leaves[later]['safe']);self.assertTrue(scope.leaves[unrelated]['safe'])
        self.assertTrue(later.exists());self.assertTrue(unrelated.exists())

    def test_runtime_exception_preserves_every_mounted_owned_leaf_and_primary(self):
        scope=e.WorkerLeaves();link,library,caller_leaf,runtime,command=self.runtime_inputs(scope)
        error=ValueError('unverified runtime');token=e._LEAF_SCOPE.set(scope)
        try:
            with patch.object(e,'_run',side_effect=error),self.assertRaises(ValueError) as caught:
                e.run(command,runtime,phase='runtime')
            self.assertIs(caught.exception,error)
        finally:e._LEAF_SCOPE.reset(token);scope.close()
        self.assertTrue(all(not scope.leaves[path]['safe'] for path in (link,caller_leaf,runtime)))
        self.assertEqual(library.read_bytes(),b'owned library')
        self.assertTrue(caller_leaf.exists());self.assertTrue(runtime.exists())

    def test_verified_runtime_reclaims_work_and_mounted_owned_leaves(self):
        scope=e.WorkerLeaves();link,library,caller_leaf,runtime,command=self.runtime_inputs(scope)
        token=e._LEAF_SCOPE.set(scope)
        try:
            with patch.object(e,'_run',return_value=({},clean())):
                e.run(command,runtime,phase='runtime')
        finally:e._LEAF_SCOPE.reset(token);scope.close()
        self.assertTrue(all(scope.leaves[path]['safe'] for path in (link,caller_leaf,runtime)))
        self.assertTrue(link.exists());self.assertTrue(caller_leaf.exists());self.assertTrue(runtime.exists())
        self.assertEqual(b'owned library',library.read_bytes())

    def test_candidate_final_child_stat_unlink_substitution_is_unreachable(self):
        for kind in ('file','symlink'):
            with self.subTest(kind=kind):
                scope=e.WorkerLeaves();leaf=self.leaf(scope,'child-boundary-'+kind)
                output=leaf/'candidate.o';output.write_bytes(b'owned output')
                held=self.root/('held-output-'+kind);canary=self.root/('canary-'+kind)
                canary.write_bytes(b'foreign bytes');fd=scope.leaves[leaf]['fd']
                original_stat=os.stat;checks=[]
                def substitute(name,*args,**kwargs):
                    metadata=original_stat(name,*args,**kwargs)
                    if name=='candidate.o' and kwargs.get('dir_fd')==fd:
                        checks.append(metadata.st_ino)
                        if len(checks)==2:
                            output.rename(held)
                            if kind=='file':output.write_bytes(b'foreign replacement')
                            else:output.symlink_to(canary)
                    return metadata
                with patch.object(e.os,'stat',side_effect=substitute) as inspected,patch.object(e.os,'unlink',wraps=os.unlink) as deleted:
                    scope.close()
                # No final-name check/use boundary remains to interpose upon.
                inspected.assert_not_called();deleted.assert_not_called()
                self.assertEqual(b'owned output',output.read_bytes())
                self.assertFalse(held.exists());self.assertEqual(b'foreign bytes',canary.read_bytes())
                with self.assertRaises(OSError):os.fstat(fd)

    def test_candidate_final_leaf_lstat_rmdir_substitution_is_unreachable(self):
        for kind in ('directory','file','symlink'):
            with self.subTest(kind=kind):
                scope=e.WorkerLeaves();leaf=self.leaf(scope,'leaf-boundary-'+kind)
                held=self.root/('held-leaf-'+kind);canary=self.root/('target-'+kind);canary.mkdir()
                original_lstat=Path.lstat;checks=[]
                def substitute(path,*args,**kwargs):
                    metadata=original_lstat(path,*args,**kwargs)
                    if path==leaf:
                        checks.append(metadata.st_ino)
                        if len(checks)==2:
                            path.rename(held)
                            if kind=='directory':path.mkdir()
                            elif kind=='file':path.write_bytes(b'foreign replacement')
                            else:path.symlink_to(canary,target_is_directory=True)
                    return metadata
                with patch.object(Path,'lstat',substitute),patch.object(e.os,'rmdir',wraps=os.rmdir) as deleted:
                    scope.close()
                self.assertEqual([],checks);deleted.assert_not_called()
                self.assertTrue(leaf.is_dir());self.assertFalse(held.exists());self.assertTrue(canary.is_dir())

    def test_candidate_retention_never_deletes_and_preserves_absence_facts(self):
        for state in ('prelaunch','verified','unknown'):
            with self.subTest(state=state):
                scope=e.WorkerLeaves();leaf=self.leaf(scope,'retention-'+state)
                output=leaf/'output';output.write_bytes(b'retained diagnostic')
                if state!='prelaunch':scope.call(leaf,lambda: ({},clean() if state=='verified' else None))
                safe=scope.leaves[leaf]['safe'];self.assertEqual(state!='unknown',safe)
                with patch.object(e.os,'unlink') as unlink,patch.object(e.os,'rmdir') as rmdir,patch('shutil.rmtree') as rmtree:
                    scope.close()
                unlink.assert_not_called();rmdir.assert_not_called();rmtree.assert_not_called()
                self.assertIs(safe,scope.leaves[leaf]['safe'])
                self.assertEqual({'status':'retained','deletionAttempted':False,
                    'reason':'exclusive-deletion-authority-unavailable'},scope.leaves[leaf]['cleanup'])
                self.assertEqual(b'retained diagnostic',output.read_bytes())

    def test_candidate_retention_closes_all_descriptors_once_despite_close_error(self):
        scope=e.WorkerLeaves();leaves=[self.leaf(scope,'close-'+str(i)) for i in range(2)]
        descriptors=[scope.leaves[leaf]['fd'] for leaf in leaves];original_close=os.close
        def close(fd):
            original_close(fd)
            if fd==descriptors[0]:raise OSError('authored close uncertainty after close')
        with patch.object(e.os,'close',side_effect=close) as closed:
            scope.close();scope.close()
        self.assertEqual(descriptors,[call.args[0] for call in closed.call_args_list])
        self.assertTrue(all(scope.leaves[leaf]['fd'] is None for leaf in leaves))
        for fd in descriptors:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertTrue(all(leaf.is_dir() for leaf in leaves))

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
        admitted_profile=contract._read_profile_snapshot()
        summary={'runtimeRequestCount':0,'behaviorStatus':'not-attempted'}
        # The production namespace gate remains active; the repository fixture
        # path includes its required trusted-copy namespace.
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'verified_visible_snapshot',return_value=admitted_profile),patch.object(e,'validated_observations',return_value=[]),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'compile_sequence',side_effect=compile_snapshot),patch.object(e,'summarize',return_value=summary),patch.object(e,'digest',return_value='a'*64),patch.object(e,'validate_exchange'),patch.object(e,'write_json'):
            report=e.evaluate(candidate,self.root/'output',self.root/'helper',self.root/'caller',visible,self.root/'observations')
        self.assertEqual(report['candidateSha256'],hashlib.sha256(original).hexdigest())
        self.assertNotEqual(report['candidateSha256'],hashlib.sha256(candidate.read_bytes()).hexdigest())
        self.assertEqual(admitted_profile.sha256,report['profileSha256'])


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
        declared_profile=e.load_profile()
        for mode,size in ((stat.S_IFIFO,1),(stat.S_IFREG,declared_profile['bounds']['fileSizeBytes']+1)):
            def metadata(fd):
                row=original_fstat(fd)
                if stat.S_ISREG(row.st_mode):
                    return SimpleNamespace(st_dev=row.st_dev,st_ino=row.st_ino,st_mode=mode,st_size=size,
                                           st_mtime_ns=row.st_mtime_ns,st_ctime_ns=row.st_ctime_ns)
                return row
            with self.subTest(mode=mode),patch.object(e,'load_profile',return_value=declared_profile),patch.object(e,'_handoff_parent',return_value=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)),patch.object(e.os,'fstat',side_effect=metadata),patch.object(e.os,'read') as read,patch.object(e.os,'close',side_effect=original_close) as close:
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
        declared_profile=e.load_profile()
        def failed_close(fd):
            original_close(fd)
            raise OSError('authored close uncertainty')
        for action in (lambda:e.capture_artifact(source,deadline=self.end),
                       lambda:e.copy_input(artifact,self.root/'close-copy',deadline=self.end)):
            parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            with patch.object(e,'load_profile',return_value=declared_profile),patch.object(e,'_handoff_parent',return_value=parent),patch.object(e.os,'close',side_effect=failed_close) as close:
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
        # Exercise only post-admission byte continuity using an explicit inert
        # producer boundary; the real boundary refuses without protected authority.
        with patch.object(e,'_capture_producer_artifact',side_effect=capture) as snapshots,patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'copy_input',side_effect=copied),patch.object(e,'_run',side_effect=worker):
            statuses,artifacts=e.compile_sequence(e.CapturedArtifact(b'authored source'),initial_deadline=self.end)
        self.assertEqual(['preprocess','compile','link'],calls)
        self.assertEqual(3,snapshots.call_count)
        self.assertTrue(all(row['status']=='passed' for row in statuses.values()))
        self.assertEqual([row[3] for row in phases],[artifacts[row[0]].data for row in phases])
        self.assertFalse(artifacts['link'].evidence()['producerOriginQualified'])
        self.assertFalse(artifacts['link'].evidence()['ordinaryMountAbaQualified'])

    def test_producer_boundary_refuses_stable_replacements_without_reading_a_new_baseline(self):
        for name in ('candidate.i','candidate.o','libcandidate.so','expected.i'):
            path=self.root/name;path.write_bytes(b'authored substituted output')
            with self.subTest(name=name),patch.object(e,'capture_artifact') as capture:
                with self.assertRaisesRegex(ValueError,'producer-output authority unavailable'):
                    e._capture_producer_artifact(path,deadline=self.end)
                capture.assert_not_called()
            self.assertEqual(b'authored substituted output',path.read_bytes())
        self.now=self.end
        with self.assertRaises(TimeoutError):
            e._capture_producer_artifact(self.root/'expected.i',deadline=self.end)

    def test_each_compile_phase_refuses_pre_capture_substitution_and_stops_propagation(self):
        boundary=e._capture_producer_artifact
        graph=[('preprocess','candidate.c','candidate.i'),('compile','candidate.i','candidate.o'),('link','candidate.o','libcandidate.so')]
        for stop in range(3):
            calls=[];retained=[];leaves=[]
            def leaf(label):
                path=self.root/(str(stop)+'-'+label);path.mkdir();leaves.append(path);return path
            def worker(argv,work,**kwargs):
                phase,_,output=graph[len(calls)];calls.append(phase)
                (work/output).write_bytes(b'authored producer bytes')
                (work/output).write_bytes(b'authored stable replacement before first capture')
                return {'status':'passed','execution':{'authored':'producer execution only'},
                        'producerOriginQualified':True},None
            def handoff(path,**kwargs):
                # Earlier phases are synthetic admitted boundaries solely to
                # reach each real refusing consumer. Flags cannot authorize it.
                return boundary(path,**kwargs) if len(calls)==stop+1 else e.capture_artifact(path,**kwargs)
            with self.subTest(phase=graph[stop][0]),patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'run',side_effect=worker),patch.object(e,'_capture_producer_artifact',side_effect=handoff):
                statuses,artifacts=e.compile_sequence(e.CapturedArtifact(b'authored source'),retain=lambda name,row:retained.append((name,row)),initial_deadline=self.end)
                self.assertEqual([row[0] for row in graph[:stop+1]],calls)
                self.assertEqual([row[0] for row in graph[:stop]],list(artifacts))
                refused=statuses[graph[stop][0]]
                self.assertEqual('unknown',refused['status'])
                self.assertIn('producer-output authority unavailable',refused['reason'])
                self.assertEqual({'authored':'producer execution only'},refused['execution'])
                self.assertNotIn('outputArtifact',refused)
                self.assertEqual(refused,retained[-1][1])
                self.assertEqual(b'authored stable replacement before first capture',(leaves[-1]/graph[stop][2]).read_bytes())

    def _producer_refusal_evaluation_fixture(self):
        from test_process_results import observations
        contracts=self.root/'contracts';contracts.mkdir()
        for path in (e.BASE/'contracts').iterdir():
            if path.is_file():(contracts/path.name).write_bytes(path.read_bytes())
        private=self.root/'private';private.mkdir()
        for name in ('original.c','original.h'):(private/name).write_bytes(b'authored reference fixture')
        for name in ('candidate.c','helper','caller'):(self.root/name).write_bytes(b'authored inert input')
        return observations()

    def test_unqualified_producer_cannot_admit_candidate_or_request_runtime(self):
        observations=self._producer_refusal_evaluation_fixture();calls=[]
        def worker(argv,work,**kwargs):
            calls.append(argv);(work/'candidate.i').write_bytes(b'authored replacement before capture')
            return {'status':'passed','execution':{'authored':'execution is not output authority'}},None
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'validated_observations',return_value=observations),patch.object(e,'run',side_effect=worker),patch.object(e,'probe') as probe,patch.object(e,'export_inventory') as exports:
            report=e._evaluate(self.root/'candidate.c',self.root/'output',self.root/'helper',self.root/'caller',self.root,self.root/'observations.json')
        self.assertEqual(1,len(calls));probe.assert_not_called();exports.assert_not_called()
        self.assertFalse(report['admitted']);self.assertIsNone(report['runtimeInputs'])
        self.assertEqual(0,report['runtimeRequestCount']);self.assertEqual(24,report['admissionRefusedCount'])
        self.assertEqual('unknown',report['phases']['preprocess']['status'])
        for name in ('compile','link','exports','declarations','gccAssertions','load','behavior'):
            self.assertEqual('not-attempted',report['phases'][name]['status'])
        receipt=json.loads((self.root/'output/preprocess.json').read_bytes())
        self.assertEqual({'authored':'execution is not output authority'},receipt['execution'])
        self.assertNotIn('outputArtifact',receipt)
        self.assertIsNone(report['processBehaviorRate']);self.assertIsNone(report['formalStructuralScore'])

    def test_expected_preprocess_also_refuses_unqualified_output_before_assertions(self):
        observations=self._producer_refusal_evaluation_fixture();calls=[]
        def compile_fixture(source,*,retain,initial_deadline):
            for phase in ('preprocess','compile','link'):retain(phase,{'status':'passed'})
            return {},{'preprocess':e.CapturedArtifact(b'authored candidate preprocessed'),
                       'link':e.CapturedArtifact(b'authored linked library')}
        def worker(argv,work,**kwargs):
            calls.append(argv)
            if '-o' in argv:(work/'expected.i').write_bytes(b'authored substituted expected output')
            return {'status':'passed','execution':{'authored':'expected execution only'}},None
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'validated_observations',return_value=observations),patch.object(e,'compile_sequence',side_effect=compile_fixture),patch.object(e,'run',side_effect=worker),patch.object(e,'probe',return_value={'status':'supported','interfaces':{'acp_state':{}}}),patch.object(e,'compare_descriptors',return_value={'status':'passed'}),patch.object(e,'layout_assertions',return_value='authored inert assertion') as assertions,patch.object(e,'resolve_declaration',return_value={'sizeBits':64}),patch.object(e,'export_inventory',return_value={'status':'unknown'}):
            report=e._evaluate(self.root/'candidate.c',self.root/'output',self.root/'helper',self.root/'caller',self.root,self.root/'observations.json')
        retained=json.loads((self.root/'output/gcc-expected-preprocess.json').read_bytes())
        self.assertEqual('unknown',retained['status']);self.assertNotIn('outputArtifact',retained)
        self.assertIn('producer-output authority unavailable',retained['reason'])
        self.assertEqual({'authored':'expected execution only'},retained['execution'])
        self.assertEqual(1,assertions.call_count)
        self.assertEqual('candidate.i',assertions.call_args.args[0].name)
        self.assertEqual('unknown',report['phases']['gccAssertions']['status'])
        self.assertFalse(report['admitted']);self.assertEqual(0,report['runtimeRequestCount'])

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
        with patch.object(e,'_capture_producer_artifact',side_effect=e.capture_artifact),patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'run',return_value=({'status':'passed','execution':{'authored':'retained producer record'}},None)) as worker:
            statuses,artifacts=e.compile_sequence(e.CapturedArtifact(b'authored source'),initial_deadline=self.end)
        self.assertEqual('unknown',statuses['preprocess']['status']);self.assertEqual({},artifacts)
        self.assertEqual({'authored':'retained producer record'},statuses['preprocess']['execution'])
        self.assertEqual(1,worker.call_count)

    def test_probe_binds_source_helper_and_refuses_independently_substituted_launch_pin(self):
        import interface_gate_v3 as gate
        from test_identity_graph import graph
        from test_process_results import receipt
        declared_profile=gate.load_profile()
        _,artifact=self.artifact();source=e.copy_input(artifact,self.root/'probe.i',deadline=self.end)
        helper=self.root/'helper';helper.write_bytes(b'authored inert helper')
        helper_pin=e.CopiedInput(helper,e._file_version(helper.stat()),hashlib.sha256(helper.read_bytes()).hexdigest()).pin()
        expected=e._input_pins([source]);sha=helper_pin['sha256'];commands=[]
        for wrong in (False,True):
            pins={**expected,str(helper):helper_pin}
            if wrong:pins[str(source.path)]={**pins[str(source.path)],'sha256':'f'*64}
            raw=receipt(stdout=json.dumps(graph()).encode(),phase='probe',caller=str(helper),caller_sha=sha,input_pins=pins)
            with patch.object(gate,'profile',return_value=declared_profile),patch.object(gate,'bounded_run',return_value=raw) as worker:
                if wrong:
                    with self.assertRaisesRegex(ValueError,'launch pins differ'):
                        gate.probe(source.path,helper,self.root,{},deadline=self.end,expected_inputs=expected)
                else:
                    value=gate.probe(source.path,helper,self.root,{},deadline=self.end,expected_inputs=expected)
                    self.assertEqual(artifact.sha256,value['inputBindings']['sourceSha256'])
                    commands.append(worker.call_args.args[0])
        self.assertIn(['--ro-bind',str(source.path),'/work/probe.i'],[commands[0][n:n+3] for n in range(len(commands[0]))])

    def test_shared_helper_probe_uses_original_admission_and_refuses_prelaunch_replacement(self):
        import interface_gate_v3 as gate
        from test_identity_graph import graph
        from test_process_results import receipt
        declared=gate.load_profile();work=self.root/'shared-work';work.mkdir()
        source=e.copy_input(e.CapturedArtifact(b'authored source'),work/'source.i',deadline=self.end)
        helper=self.root/'shared-helper';helper.write_bytes(b'authored helper A')
        admitted=e._pin_files([helper],self.end);saved=deepcopy(admitted)
        inputs=e._input_pins([source]);pins={**inputs,**admitted};sha=admitted[str(helper)]['sha256']
        result=receipt(stdout=json.dumps(graph()).encode(),phase='probe',caller=str(helper),caller_sha=sha,input_pins=pins)
        self.assertTrue(gate._complete_execution(result))
        with patch.object(gate,'profile',return_value=declared),patch.object(gate,'bounded_run',return_value=result) as worker:
            value=gate.probe(source.path,helper,work,{},deadline=self.end,expected_inputs=inputs,expected_helper=admitted)
        self.assertEqual(sha,value['inputBindings']['helperSha256']);self.assertEqual(saved,admitted)
        command=worker.call_args.args[0]
        self.assertIn(['--ro-bind',str(helper),'/probe'],[command[i:i+3]for i in range(len(command))])
        self.assertEqual(self.end,worker.call_args.kwargs['phase_deadline'])
        self.assertNotIn(str(helper),inputs)
        helper.write_bytes(b'authored helper B')
        with patch.object(gate,'bounded_run',side_effect=AssertionError('replaced helper must refuse before launch')) as worker:
            with self.assertRaisesRegex(ValueError,'handoff input differs'):
                gate.probe(source.path,helper,work,{},deadline=self.end,expected_inputs=inputs,expected_helper=admitted)
        worker.assert_not_called();self.assertEqual(saved,admitted)

    def test_shared_helper_probe_executed_b_restored_a_and_lateness_retain_original_receipts(self):
        import interface_gate_v3 as gate
        from test_identity_graph import graph
        from test_process_results import receipt
        declared=gate.load_profile();work=self.root/'shared-late-work';work.mkdir()
        source=e.copy_input(e.CapturedArtifact(b'authored source'),work/'source.i',deadline=self.end)
        helper=self.root/'shared-late-helper';original=b'authored helper A';helper.write_bytes(original)
        admitted=e._pin_files([helper],self.end);inputs=e._input_pins([source])
        observed=[]
        for mutation in ('executed-b','late-return'):
            self.now=10.0
            def worker(*args,**kwargs):
                if mutation=='executed-b':helper.write_bytes(b'authored helper B')
                actual=e._pin_files([helper],self.end)
                raw=receipt(stdout=json.dumps(graph()).encode(),phase='probe',caller=str(helper),
                            caller_sha=actual[str(helper)]['sha256'],input_pins={**inputs,**actual})
                self.assertTrue(gate._complete_execution(raw));observed.append(raw)
                helper.write_bytes(original)
                if mutation=='late-return':self.now=self.end
                return raw
            with self.subTest(mutation=mutation),patch.object(gate,'profile',return_value=declared), \
                    patch.object(gate,'bounded_run',side_effect=worker):
                with self.assertRaises((ValueError,TimeoutError)) as caught:
                    gate.probe(source.path,helper,work,{},deadline=self.end,expected_inputs=inputs,expected_helper=admitted)
            self.assertIs(observed[-1],caught.exception.bounded_result)
        with patch.object(gate,'bounded_run',side_effect=AssertionError('original end already expired')) as worker:
            with self.assertRaises(TimeoutError):
                gate.probe(source.path,helper,work,{},deadline=self.end,expected_inputs=inputs,expected_helper=admitted)
        worker.assert_not_called()

    def test_evaluator_shared_helper_swap_stops_declaration_admission_and_all_runtime_requests(self):
        import interface_gate_v3 as gate
        from test_identity_graph import graph
        from test_process_results import receipt,observations
        candidate=self.root/'shared-candidate.c';candidate.write_bytes(b'authored candidate')
        helper=self.root/'shared-evaluator-helper';helper.write_bytes(b'authored helper A')
        caller=self.root/'shared-caller';caller.write_bytes(b'authored caller')
        captured=e.capture_artifact;original_probe=e.probe;original_pin=e._pin_files
        declared=gate.load_profile()
        contracts=self.root/'contracts';contracts.mkdir()
        (contracts/'candidate-build-profile.json').write_bytes((e.BASE/'contracts/candidate-build-profile.json').read_bytes())
        (self.root/'worker_exec_proof.py').write_bytes((e.BASE/'worker_exec_proof.py').read_bytes())
        admitted=[];probe_inputs=[];workers=[];leaves=[];expire_admission=False
        def pin(paths,deadline=None):
            if expire_admission:self.now=deadline
            value=original_pin(paths,deadline);admitted.append((deepcopy(value),deadline));return value
        def capture(path,**kwargs):
            if Path(path) in (e.BASE/'private/original.c',e.BASE/'private/original.h'):
                return e.CapturedArtifact(b'authored private fixture')
            return captured(path,**kwargs)
        def compile_fixture(source,*,retain,initial_deadline):
            retain('preprocess',{'status':'passed','reason':'authored inert producer'})
            return {},{'preprocess':e.CapturedArtifact(b'authored candidate preprocessed')}
        def leaf(label):
            path=self.root/('shared-'+label+'-'+str(len(leaves)));path.mkdir();leaves.append(path);return path
        def worker(command,work,*args,**kwargs):
            workers.append(kwargs['phase']);pins={}
            for i,arg in enumerate(command[:-1]):
                if arg=='--ro-bind':
                    path=Path(command[i+1])
                    if path.is_file() and path.is_relative_to(self.root):pins.update(original_pin([path],self.end))
            return receipt(stdout=json.dumps(graph()).encode(),phase='probe',caller=str(helper),
                           caller_sha=pins[str(helper)]['sha256'],input_pins=pins)
        def probe(*args,**kwargs):
            probe_inputs.append(deepcopy(kwargs['expected_helper']))
            value=original_probe(*args,**kwargs)
            if len(probe_inputs)==1:helper.write_bytes(b'authored helper B')
            return value
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root), \
                patch.object(e,'validated_observations',return_value=observations()), \
                patch.object(e,'profile',side_effect=e.load_profile),patch.object(gate,'profile',return_value=declared), \
                patch.object(e,'capture_artifact',side_effect=capture),patch.object(e,'compile_sequence',side_effect=compile_fixture), \
                patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'_pin_files',side_effect=pin), \
                patch.object(e,'probe',side_effect=probe),patch.object(gate,'bounded_run',side_effect=worker), \
                patch.object(e,'_run',side_effect=AssertionError('no later compiler or runtime launch')),patch.object(e,'validate_exchange'):
            report=e._evaluate(candidate,self.root/'shared-output',helper,caller,self.root,self.root/'unused-observations')
            self.now=10.0;expire_admission=True
            expired=e._evaluate(candidate,self.root/'shared-expired-output',helper,caller,self.root,self.root/'unused-observations')
        self.assertEqual('unknown',expired['phases']['declarations']['status'])
        self.assertEqual(0,expired['runtimeRequestCount']);self.assertEqual(24,len(expired['scenarios']))
        self.assertEqual(1,len(admitted));self.assertEqual(2,len(probe_inputs))
        self.assertEqual(self.end,admitted[0][1])
        self.assertEqual(admitted[0][0],probe_inputs[0]);self.assertEqual(probe_inputs[0],probe_inputs[1])
        self.assertEqual(['probe'],workers)
        self.assertEqual('unknown',report['phases']['declarations']['status'])
        self.assertFalse(report['admitted']);self.assertEqual(0,report['runtimeRequestCount'])
        self.assertEqual(24,len(report['scenarios']))
        self.assertEqual('not-attempted',report['phases']['gccAssertions']['status'])

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
        declared_profile=gate.load_profile()
        admitted_profile=contract._read_profile_snapshot()
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
        # Reference receipts and their later replay share the same canonical profile path.
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root):
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
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'verified_visible_snapshot',return_value=admitted_profile),patch.object(e,'validated_observations',return_value=observations),patch.object(e,'profile',side_effect=e.load_profile),patch.object(e,'new_worker_leaf',side_effect=leaf),patch.object(e,'copy_input',side_effect=copied),patch.object(e,'_run',side_effect=compiler),patch.object(e,'_capture_producer_artifact',side_effect=e.capture_artifact),patch.object(gate,'profile',return_value=declared_profile),patch.object(gate,'bounded_run',side_effect=inspection),patch.object(e,'validate_exchange'):
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


class OwnedJsonEvidence(unittest.TestCase):
    """Authored owned files and mocked descriptors; no worker/FIFO/native work."""
    def setUp(self):
        import bounded_runtime as runtime
        self.runtime=runtime
        self.temp=tempfile.TemporaryDirectory(dir=static_temp('static-process'))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        base=patch.object(runtime,'BASE',self.root);base.start();self.addCleanup(base.stop)
        profile=patch.object(runtime,'load_profile_with_digest',side_effect=AssertionError('writer must not acquire profile'))
        profile.start();self.addCleanup(profile.stop)

    def encoded(self,value):
        stream=io.StringIO();json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
        return stream.getvalue().encode('utf-8')

    def consumer(self,writer):
        # Isolate only the real nested retain seam, never execute the evaluator.
        tree=ast.parse(Path(e.__file__).read_text())
        evaluate=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_evaluate')
        retain=next(n for n in evaluate.body if isinstance(n,ast.FunctionDef) and n.name=='retain')
        reopened=Mock(side_effect=AssertionError('pathname digest/reopen forbidden'))
        namespace={'output':self.root,'write_json':writer,'evidence':{},'digest':reopened}
        exec(compile(ast.Module(body=[deepcopy(retain)],type_ignores=[]),'<owned-retain-seam>','exec'),namespace)
        return namespace['retain'],namespace['evidence'],reopened

    def test_exact_existing_unicode_indentation_ascii_and_lf_encoding(self):
        value={'z':['é','😀','surrogate:\ud800','line\nbreak'], 'a':None,'float':float('nan')}
        expected=self.encoded(value);path=self.root/'unicode.json';original=json.dump
        with patch.object(self.runtime.json,'dump',wraps=original) as dump,patch.object(self.runtime,'digest',side_effect=AssertionError('no file digest')):
            result=self.runtime.write_json(path,value)
        self.assertEqual(1,dump.call_count);self.assertEqual(expected,path.read_bytes())
        self.assertEqual(hashlib.sha256(expected).hexdigest(),result)
        self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(16777216,self.runtime.enforced_process_limits()['RLIMIT_FSIZE']['hard'])

    def test_short_writes_commit_one_immutable_serialization_even_if_value_changes(self):
        value={'value':'authored original'};expected=self.encoded(value);path=self.root/'short.json'
        original_write=os.write;original_dump=json.dump;offered=[]
        def write(fd,data):
            value['value']='changed after serialization'
            offered.append(bytes(data));return original_write(fd,data[:2])
        with patch.object(self.runtime.os,'write',side_effect=write),patch.object(self.runtime.json,'dump',wraps=original_dump) as dump:
            result=self.runtime.write_json(path,value)
        self.assertGreater(len(offered),1);self.assertEqual(1,dump.call_count)
        self.assertEqual(expected,path.read_bytes());self.assertEqual(hashlib.sha256(expected).hexdigest(),result)
        self.assertNotEqual(expected,self.encoded(value))

    def test_each_write_is_bounded_without_changing_encoded_bytes(self):
        value={'payload':'x'*70000};expected=self.encoded(value);original=os.write;amounts=[]
        def write(fd,data):amounts.append(len(data));return original(fd,data)
        with patch.object(self.runtime.os,'write',side_effect=write):result=self.runtime.write_json(self.root/'chunks.json',value)
        self.assertGreater(len(amounts),1);self.assertLessEqual(max(amounts),65536)
        self.assertEqual(hashlib.sha256(expected).hexdigest(),result)

    def test_retain_never_reopens_replaced_removed_or_fake_fifo_path(self):
        value={'message':'authored retained value'};expected=self.encoded(value)
        for change in ('replacement','removal','fifo-fake'):
            with self.subTest(change=change):
                def writer(path,item):
                    digest=self.runtime.write_json(path,item)
                    path.unlink()
                    if change=='replacement':path.write_bytes(b'authored replacement bytes')
                    # fifo-fake deliberately supplies no real special file. Any
                    # attempted digest models a blocking FIFO observer and fails.
                    return digest
                retain,evidence,reopen=self.consumer(writer)
                actual=retain(change,value)
                self.assertEqual(hashlib.sha256(expected).hexdigest(),actual)
                self.assertEqual({change+'.json':actual},evidence);reopen.assert_not_called()

    def test_exclusive_outside_and_mocked_special_descriptor_fail_before_payload(self):
        path=self.root/'existing.json';path.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):self.runtime.write_json(path,{})
        self.assertEqual(b'keep',path.read_bytes())
        with self.assertRaisesRegex(ValueError,'outside'):self.runtime.write_json(self.root.parent/'outside-owned-json.json',{})
        with patch.object(self.runtime.os,'open',return_value=1234) as opened,patch.object(self.runtime.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFIFO,st_size=0)),patch.object(self.runtime.os,'write') as write,patch.object(self.runtime.os,'fchmod') as chmod,patch.object(self.runtime.os,'close') as close:
            with self.assertRaisesRegex(ValueError,'regular file'):self.runtime.write_json(self.root/'mock-special.json',{})
        flags=opened.call_args.args[1]
        for flag in (os.O_CREAT,os.O_EXCL,os.O_NOFOLLOW,os.O_NONBLOCK,os.O_CLOEXEC):self.assertEqual(flag,flags&flag)
        self.assertEqual(0o600,opened.call_args.args[2]);write.assert_not_called();chmod.assert_not_called();close.assert_called_once_with(1234)

    def test_byte_bound_admits_exact_size_then_refuses_before_payload_write(self):
        value={'value':'authored'};expected=self.encoded(value)
        for maximum in (len(expected),len(expected)-1):
            with self.subTest(maximum=maximum),patch.object(self.runtime,'enforced_process_limits',return_value={'RLIMIT_FSIZE':{'hard':maximum}}):
                path=self.root/('bound-'+str(maximum)+'.json')
                if maximum==len(expected):
                    self.assertEqual(hashlib.sha256(expected).hexdigest(),self.runtime.write_json(path,value))
                else:
                    with patch.object(self.runtime.os,'write') as write,self.assertRaisesRegex(ValueError,'byte bound'):self.runtime.write_json(path,value)
                    write.assert_not_called();self.assertEqual(b'',path.read_bytes())

    def test_write_chmod_and_close_errors_propagate_without_evidence_credit(self):
        original_close=os.close
        for bad in (0,-1,True,100000):
            with self.subTest(write_result=bad),patch.object(self.runtime.os,'write',return_value=bad),patch.object(self.runtime.os,'close',side_effect=original_close) as close:
                with self.assertRaisesRegex(ValueError,'short write'):self.runtime.write_json(self.root/('bad-'+str(bad)+'.json'),{})
                self.assertEqual(1,close.call_count)
        for failing in ('write','fchmod','close'):
            error=OSError('authored '+failing+' error')
            def close_failure(fd):original_close(fd);raise error
            side_effect=close_failure if failing=='close' else error
            retain,evidence,reopen=self.consumer(self.runtime.write_json)
            with self.subTest(failing=failing),patch.object(self.runtime.os,failing,side_effect=side_effect),self.assertRaises(OSError) as caught:
                retain('error-'+failing,{})
            self.assertIs(error,caught.exception);self.assertEqual({},evidence);reopen.assert_not_called()



class ProfileCarryLifecycle(unittest.TestCase):
    def test_evaluation_and_cleanup_keep_admitted_a_when_path_reader_now_supplies_b(self):
        import bounded_runtime as runtime
        import interface_gate_v3 as gate
        from test_contracts import authored_profile_bytes
        a=contract._ProfileSnapshot(authored_profile_bytes('A'))
        b=contract._ProfileSnapshot(authored_profile_bytes('B'))
        root=Path('/authored/build/acp-decomp-effectiveness/callable-library-v3/profile-control')
        scope=Mock();events=[]
        def operation(*args):
            for loader in (e.load_profile_with_digest,runtime.load_profile_with_digest,gate.load_profile_with_digest):
                value,digest=loader();events.append(('body',value['gccIdentity']['version'],digest))
            return {'profileSha256':e.load_profile_with_digest()[1]}
        def cleanup():events.append(('close',e._LEAF_SCOPE.get() is scope,contract._PROFILE_SNAPSHOT.get() is a))
        scope.close.side_effect=cleanup
        previous_leaf=e._LEAF_SCOPE.get();previous_profile=contract._PROFILE_SNAPSHOT.get()
        with contract.profile_scope(b),patch.object(e,'BASE',root),patch.object(Path,'resolve',autospec=True,side_effect=lambda path,strict=False:path),patch.object(e,'verified_visible_snapshot',return_value=a) as admission,patch.object(e,'WorkerLeaves',return_value=scope),patch.object(e,'_evaluate',side_effect=operation),patch.object(contract,'_bounded_json_snapshot',return_value=b.raw) as pathname:
            report=e.evaluate(root/'candidate',root/'output',root/'helper',root/'caller',root/'visible',root/'observations')
            self.assertEqual(a.sha256,report['profileSha256'])
            self.assertIs(b,contract._PROFILE_SNAPSHOT.get());self.assertIs(previous_leaf,e._LEAF_SCOPE.get())
            pathname.assert_not_called();admission.assert_called_once_with(root/'visible')
        self.assertEqual([('body','A',a.sha256)]*3+[('close',True,True)],events)
        self.assertIs(previous_profile,contract._PROFILE_SNAPSHOT.get());self.assertIs(previous_leaf,e._LEAF_SCOPE.get())
        scope.close.assert_called_once_with()

    def test_primary_cleanup_failure_and_both_context_resets_preserve_owned_order(self):
        from test_contracts import authored_profile_bytes
        admitted=contract._ProfileSnapshot(authored_profile_bytes('A'))
        outer=contract._ProfileSnapshot(authored_profile_bytes('B'))
        root=Path('/authored/build/acp-decomp-effectiveness/callable-library-v3/profile-control')
        for body_fails,cleanup_fails in ((False,False),(True,False),(False,True),(True,True)):
            with self.subTest(body=body_fails,cleanup=cleanup_fails):
                primary=ValueError('authored evaluation failure');cleanup_error=OSError('authored cleanup failure')
                scope=Mock();events=[];caught=None;answer=None
                def operation(*args):
                    events.append(('body',contract._PROFILE_SNAPSHOT.get() is admitted))
                    if body_fails:raise primary
                    return 'authored answer'
                def cleanup():
                    events.append(('close',e._LEAF_SCOPE.get() is scope,contract._PROFILE_SNAPSHOT.get() is admitted))
                    if cleanup_fails:raise cleanup_error
                scope.close.side_effect=cleanup
                before_profile=contract._PROFILE_SNAPSHOT.get();before_leaf=e._LEAF_SCOPE.get()
                with contract.profile_scope(outer),patch.object(e,'BASE',root),patch.object(Path,'resolve',autospec=True,side_effect=lambda path,strict=False:path),patch.object(e,'verified_visible_snapshot',return_value=admitted),patch.object(e,'WorkerLeaves',return_value=scope),patch.object(e,'_evaluate',side_effect=operation):
                    try:answer=e.evaluate(root/'candidate',root/'output',root/'helper',root/'caller',root/'visible',root/'observations')
                    except BaseException as failure:caught=failure
                    self.assertIs(outer,contract._PROFILE_SNAPSHOT.get());self.assertIs(before_leaf,e._LEAF_SCOPE.get())
                self.assertIs(before_profile,contract._PROFILE_SNAPSHOT.get());self.assertIs(before_leaf,e._LEAF_SCOPE.get())
                self.assertEqual([('body',True),('close',True,True)],events);scope.close.assert_called_once_with()
                expected=primary if body_fails else cleanup_error if cleanup_fails else None
                self.assertIs(expected,caught)
                if expected is None:self.assertEqual('authored answer',answer)
                else:self.assertIsNone(answer)
                if body_fails and cleanup_fails:
                    self.assertEqual(['worker leaf cleanup failed after evaluation failure'],primary.__notes__)


if __name__=='__main__':unittest.main()
