"""Compiler/helper filesystem boundary regressions with harmless host sentinels."""
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bounded_runtime import private_directory,write_json,digest
from interface_gate_v2 import probe
from evaluate_candidate_v2 import run,phase_command,environment
from build_contract import profile
class ProbeIsolation(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  for number in range(1,1000):
   cls.evidence=ROOT/'tests'/f'probe-isolation-{number:03d}'
   try:private_directory(cls.evidence);break
   except FileExistsError:continue
  cls.helper=ROOT/'toolchain-001/record_identity_probe'
  cls.header=(ROOT/'private/original.h').read_text()
  cls.sentinel=cls.evidence/'host-only-sentinel.h'
  cls.sentinel.write_text('#error ACP_HOST_SENTINEL_CONTENT_MUST_NOT_BE_READ_1507\n')
 @classmethod
 def check_refused(cls,work,source,name):
  result=probe(source,cls.helper,work,environment(work))
  write_json(cls.evidence/(name+'-probe.json'),result)
  raw=bytes.fromhex(result['execution']['stderrHex'])
  assert result['status']=='refused'
  assert b'ACP_HOST_SENTINEL_CONTENT_MUST_NOT_BE_READ_1507' not in raw
  assert b'file not found' in raw
  assert result['execution']['kernelScope']['finalAbsenceVerified']
  assert result['inputBindings']['inputsUnchanged']
  assert result['inputBindings']['sourceSha256']==digest(source)
  return result
 def test_macro_emitted_include_after_compile_failure(self):
  work=private_directory(self.evidence/'source-path')
  (work/'candidate.c').write_text('#define ACP_HASH #\nACP_HASH include "'+str(self.sentinel)+'"\n'+self.header)
  status,result=run(phase_command(work,profile()['commands']['preprocess']),work)
  write_json(self.evidence/'source-preprocess.json',status)
  self.assertEqual(status['status'],'passed')
  self.assertIn(b'# include', (work/'candidate.i').read_bytes())
  status,result=run(phase_command(work,profile()['commands']['compile']),work)
  write_json(self.evidence/'source-compile.json',status)
  self.assertEqual(status['status'],'failed')
  self.check_refused(work,work/'candidate.i','source')
 def test_direct_preprocessed_helper_include(self):
  work=private_directory(self.evidence/'direct-path')
  source=work/'candidate.i';source.write_text('# include "'+str(self.sentinel)+'"\n'+self.header)
  self.check_refused(work,source,'direct')
 def test_probe_refuses_host_source_argument(self):
  work=private_directory(self.evidence/'outside-source')
  with self.assertRaises(ValueError):probe(self.sentinel,self.helper,work,environment(work))
 def test_expected_trusted_header_is_available_only_in_own_work(self):
  work=private_directory(self.evidence/'expected-path')
  (work/'original.h').write_text(self.header)
  source=work/'source.c';source.write_text('#include "original.h"\n')
  result=probe(source,self.helper,work,environment(work));write_json(self.evidence/'expected-probe.json',result)
  self.assertEqual(result['status'],'supported')
if __name__=='__main__':unittest.main()
