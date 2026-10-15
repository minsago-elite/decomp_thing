import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from build_contract import write_visible, verify_visible, BASE
from interface_gate_v2 import compare_descriptors, layout_assertions, REQUIRED
from bounded_runtime import bounded_run, digest
from evaluate_candidate_v2 import validated_observations, phase_command, run
class Contracts(unittest.TestCase):
    def test_visible_roundtrip_and_mutation(self):
        with tempfile.TemporaryDirectory(dir=BASE) as t:
            p=Path(t);write_visible(p);verify_visible(p)
            (p/'prompt.txt').write_text('other')
            with self.assertRaises(ValueError):verify_visible(p)
    def test_missing_identity_and_cycles_refuse(self):
        for item in ({'status':'refused','diagnostics':['cycle']},{'status':'supported','interfaces':{}}):
            self.assertFalse(compare_descriptors(item,item)['accepted'])
    def test_structural_compare_ignores_local_ids(self):
        d={'status':'supported','target':'x','interfaces':{k:{'kind':'integer','bits':32,'signed':True} for k in REQUIRED},'provenance':['local-id-1']}
        b=json.loads(json.dumps(d));b['provenance']=['local-id-2'];self.assertTrue(compare_descriptors(d,b)['accepted'])
        b['interfaces']['acp_mix']['signed']=False;self.assertFalse(compare_descriptors(d,b)['accepted'])
    def test_missing_gcc_binding_refuses(self):
        with self.assertRaises(ValueError):layout_assertions(Path('/source'),{'interfaces':{'x':{'kind':'record','sizeBits':32,'alignBits':32,'fields':[]}}})
    def test_streaming_overflow_retains_bound_and_cleanup(self):
        with tempfile.TemporaryDirectory(dir=BASE) as t:
            with self.assertRaises(ValueError) as ctx:
                bounded_run(['/usr/bin/python3','-c','import os; os.write(1,b"x"*1000000)'],Path(t),{'PATH':'/usr/bin:/bin'},output_limit=1024)
            r=ctx.exception.bounded_result
            self.assertLessEqual(len(r['stdout']),1024);self.assertTrue(r['rootReaped']);self.assertTrue(r['finalAbsenceVerified'])
    def test_private_fixture_includes_unavailable_to_candidate(self):
        with tempfile.TemporaryDirectory(dir=BASE) as t:
            root=Path(t);expected=root/'expected-gcc-work';expected.mkdir()
            (expected/'expected.c').write_text('int leaked;')
            (expected/'original.h').write_text('typedef int leaked;')
            work=root/'candidate';work.mkdir()
            for filename in ('expected.c','original.h'):
                (work/'candidate.c').write_text('#include "/work/'+filename+'"\n')
                status,result=run(phase_command(work,['/usr/bin/gcc','-E','-P','-std=c11','/work/candidate.c','-o','/work/candidate.i']),work)
                self.assertEqual(status['status'],'failed')
                self.assertIn(b'No such file or directory',result['stderr'])
                self.assertTrue(result['kernelScope']['finalAbsenceVerified'])
    def test_reference_observations_binding(self):
        with tempfile.TemporaryDirectory(dir=BASE) as t:
            p=Path(t);caller=p/'caller';caller.write_bytes(b'new caller')
            observations=p/'observations.json'
            value={'schemaVersion':2,'sourceSha256':digest(BASE/'private/original.c'),'callerSha256':digest(caller),'observations':[{'id':i,'family':'control','exitCode':0,'stdoutHex':'','stderrHex':''} for i in range(24)]}
            observations.write_text(json.dumps(value))
            self.assertEqual(len(validated_observations(observations,caller)),24)
            caller.write_bytes(b'changed caller')
            with self.assertRaises(ValueError):validated_observations(observations,caller)
            value['schemaVersion']=1;observations.write_text(json.dumps(value))
            with self.assertRaises(ValueError):validated_observations(observations,caller)
    def test_timeout_reaps(self):
        with tempfile.TemporaryDirectory(dir=BASE) as t:
            with self.assertRaises(TimeoutError) as ctx:
                bounded_run(['/usr/bin/python3','-c','while True: pass'],Path(t),{'PATH':'/usr/bin:/bin'},timeout=.1)
            self.assertTrue(ctx.exception.bounded_result['rootReaped'])
if __name__=='__main__':unittest.main()
