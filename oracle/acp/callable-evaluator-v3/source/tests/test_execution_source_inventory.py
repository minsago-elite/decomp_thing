"""Execution copies must include monitor sources and imported static support."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import freeze_v3
from static_test_support import static_temp


SUPPORT = (
    'record_identity_probe.cpp', 'preservation-manifest.json',
    'worker_exec_monitor.c', 'worker_exec_proof.py',
    'contracts/worker-exec-proof-schema.json',
    'toolchain-001/build_worker_monitor.py', 'toolchain-001/monitor_inputs.py',
    'tests/qualify_worker_exec.py', 'tests/worker_exec_barrier_harness.c',
    'tests/run_static_tests.py', 'tests/static_test_support.py',
    'tests/fixtures/historical_counterexamples.py',
    'tests/test_runtime_worker_proof.py', 'tests/test_worker_exec_proof.py',
    'tests/test_worker_proof_consumers.py',
)


class ExecutionSourceInventory(unittest.TestCase):
    def fixture(self, root):
        for name in SUPPORT:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic, never executed\n')
        (root / 'private').mkdir()
        (root / 'tests/fixtures/unselected.txt').write_bytes(b'ignored')

    def test_monitor_and_imported_support_enter_execution_copy(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-ci/test-tmp')) as temporary:
            root = Path(temporary)
            self.fixture(root)
            with patch.object(freeze_v3, 'BASE', root):
                selected = {str(Path(p).relative_to(root)) for p in freeze_v3.execution_source_paths()}
            self.assertTrue(set(SUPPORT).issubset(selected))
            self.assertNotIn('tests/fixtures/unselected.txt', selected)

    def test_missing_monitor_or_imported_support_refuses_sealing(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-ci/test-tmp')) as temporary:
            root = Path(temporary)
            self.fixture(root)
            for name in SUPPORT:
                with self.subTest(name=name):
                    path = root / name
                    raw = path.read_bytes()
                    path.unlink()
                    try:
                        with patch.object(freeze_v3, 'BASE', root):
                            with self.assertRaisesRegex(ValueError, 'missing execution source'):
                                freeze_v3.execution_source_paths()
                    finally:
                        path.write_bytes(raw)

    def test_support_symlink_is_not_admitted(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-ci/test-tmp')) as temporary:
            root = Path(temporary)
            self.fixture(root)
            support = root / 'tests/fixtures/historical_counterexamples.py'
            support.unlink()
            support.symlink_to('unselected.txt')
            with patch.object(freeze_v3, 'BASE', root):
                with self.assertRaisesRegex(ValueError, 'unsupported tree kind'):
                    freeze_v3.execution_source_paths()


if __name__ == '__main__':
    unittest.main()
