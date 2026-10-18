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
    def test_helper_and_captured_source_are_explicit_RO_overlays_not_fd_authority(self):
        work=Path('/authored/work');helper=Path('/authored/helper');source=work/'source.i'
        with patch.object(Path,'resolve',lambda path,**kwargs:path),patch('interface_gate_v3.profile',side_effect=load_profile):
            command=probe_command(helper,work,['/work/source.i'],read_only_files=(source,))
        overlays=[command[i:i+3] for i in range(len(command)-2)]
        self.assertEqual(1,overlays.count(['--ro-bind',str(helper),'/probe']))
        self.assertEqual(1,overlays.count(['--ro-bind',str(source),'/work/source.i']))
        self.assertNotIn('--bind',command);self.assertNotIn('--ro-bind-fd',command)
        self.assertNotIn('--preserve-fds',command);self.assertEqual(['/probe','/work/source.i'],command[-2:])
        # Only the actual admitted runtime preparation may substitute its owned H FD.
        with patch.object(Path,'resolve',lambda path,**kwargs:path),patch('interface_gate_v3.profile',side_effect=load_profile):
            with self.assertRaisesRegex(ValueError,'outside isolated work'):
                probe_command(helper,work,['/work/source.i'],read_only_files=(Path('/authored/private/source.i'),))
    def test_expected_fixture_not_embedded_in_public_probe(self):
        self.assertNotIn('private/original',inspect.getsource(probe_command))


if __name__=='__main__':unittest.main()
