"""Inert probe mount contract checks; real namespace refusal controls remain native gates."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from interface_gate_v3 import probe_command
import inspect
from unittest.mock import patch
from build_contract import load_profile


class ProbeIsolation(unittest.TestCase):
    def test_probe_command_has_explicit_source_and_work(self):
        with patch.object(Path,'resolve',side_effect=lambda **kw: Path('/synthetic')),patch('interface_gate_v3.profile',side_effect=load_profile):
            command=probe_command(Path('/synthetic/helper'),Path('/synthetic/work'),['/work/candidate.i'])
        for item in ('--unshare-all','--clearenv','--ro-bind','/probe','/work','/work/candidate.i'):
            self.assertIn(item,command)
        self.assertNotIn('private/original', ' '.join(command))
    def test_expected_fixture_not_embedded_in_public_probe(self):
        self.assertNotIn('private/original',inspect.getsource(probe_command))


if __name__=='__main__':unittest.main()
