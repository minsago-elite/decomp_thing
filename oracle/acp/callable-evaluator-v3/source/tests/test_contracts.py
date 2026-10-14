"""V3 inert profile/command regressions. Native qualification is a later gate."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from build_contract import load_profile, validate_profile
from evaluate_candidate_v3 import phase_command,runtime_command


class Contracts(unittest.TestCase):
    def test_profile_is_closed_without_tool_launch(self):
        value=load_profile();self.assertEqual(value['schemaVersion'],3)
        value['candidateCalled']=True
        with self.assertRaises(ValueError):validate_profile(value)
    def test_candidate_build_mounts_only_own_work(self):
        command=phase_command(Path('/synthetic/candidate'),['/usr/bin/gcc','-E','/work/candidate.c'])
        self.assertIn('/synthetic/candidate',command)
        self.assertNotIn('/synthetic/expected',command)
        self.assertIn('--unshare-all',command)
    def test_runtime_mounts_caller_and_library_without_private_sources(self):
        command=runtime_command(Path('/synthetic/caller'),Path('/synthetic/library'),0)
        self.assertIn('--clearenv',command);self.assertIn('/caller',command)
        self.assertNotIn('original.c',' '.join(command));self.assertNotIn('original.h',' '.join(command))


if __name__=='__main__':unittest.main()
