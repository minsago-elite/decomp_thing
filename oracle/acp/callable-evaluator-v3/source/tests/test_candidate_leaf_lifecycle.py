"""Pure evaluator snapshot and exact-owned leaf lifecycle controls; no processes."""
import hashlib
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

    def test_report_hashes_consumed_snapshot_not_reopened_candidate(self):
        candidate=self.root/'candidate.c';original=b'int snapshot;\n';candidate.write_bytes(original)
        for name in ('helper','caller','observations'): (self.root/name).write_bytes(b'fixture')
        visible=self.root/'visible';visible.mkdir()
        def compile_snapshot(source,retain):
            self.assertEqual(source.read_bytes(),original)
            candidate.write_bytes(b'int replaced;\n')
            return {},{}
        summary={'runtimeRequestCount':0,'behaviorStatus':'not-attempted'}
        # The production namespace gate remains active; the repository fixture
        # path includes its required trusted-copy namespace.
        with patch.object(e,'BASE',self.root),patch('bounded_runtime.BASE',self.root),patch.object(e,'verify_visible'),patch.object(e,'validated_observations',return_value=[]),patch.object(e,'profile',return_value={'bounds':{'sourceBytes':1024}}),patch.object(e,'compile_sequence',side_effect=compile_snapshot),patch.object(e,'summarize',return_value=summary),patch.object(e,'digest',return_value='a'*64),patch.object(e,'validate_exchange'),patch.object(e,'write_json'):
            report=e.evaluate(candidate,self.root/'output',self.root/'helper',self.root/'caller',visible,self.root/'observations')
        self.assertEqual(report['candidateSha256'],hashlib.sha256(original).hexdigest())
        self.assertNotEqual(report['candidateSha256'],hashlib.sha256(candidate.read_bytes()).hexdigest())


if __name__=='__main__':unittest.main()
