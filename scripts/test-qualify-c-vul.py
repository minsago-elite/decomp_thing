#!/usr/bin/env python3
"""Authored refusal controls; actual ten-case evidence is produced by qualify-c-vul.py."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('qualify_c_vul', ROOT / 'scripts/qualify-c-vul.py')
qualification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = qualification
SPEC.loader.exec_module(qualification)


def result(code=1, stderr='', stdout=''):
    return {'exitCode': code, 'stdout': stdout, 'stderr': stderr}


class EvidenceControls(unittest.TestCase):
    def test_all_ten_identifiers_and_evidence_kinds_are_required(self):
        self.assertEqual([f'{n:02}' for n in range(1, 11)], [c.number for c in qualification.CASES])
        self.assertEqual(10, len({c.cwe for c in qualification.CASES}))
        self.assertEqual({'asan', 'compiler', 'unsigned-overflow', 'ubsan', 'lsan', 'behavior'}, {c.kind for c in qualification.CASES})

    def test_success_wrong_diagnostic_and_wrong_source_never_grant_reproduction_credit(self):
        for case in qualification.CASES:
            if case.kind == 'behavior':
                continue
            for row in (result(0, 'Sanitizer'), result(1, 'unrelated error'), result(1, 'AddressSanitizer: stack-buffer-overflow\nWRITE of size 12\nwrong.c:12:3')):
                with self.subTest(case=case.number, row=row), self.assertRaises(qualification.QualificationFailure):
                    qualification.require_reproduction(case, row)

    def test_read_and_write_diagnostics_are_not_interchangeable(self):
        write, read = qualification.CASES[:2]
        for case, operation in ((write, 'READ'), (read, 'WRITE')):
            with self.subTest(case=case.number), self.assertRaises(qualification.QualificationFailure):
                qualification.require_reproduction(case, result(stderr=f'AddressSanitizer: stack-buffer-overflow\n{operation} of size 4\n{case.filename}:4:2'))

    def test_shell_canary_requires_exact_output_success_and_empty_stderr(self):
        case = qualification.CASES[-1]
        qualification.require_reproduction(case, result(0, stdout='hello\nCVUL_CANARY'))
        for row in (result(1, stdout='hello\nCVUL_CANARY'), result(0, stdout=case.expected), result(0, stderr='failure', stdout='hello\nCVUL_CANARY'), result(0, stdout='hello\nCVUL_CANARY\n')):
            with self.subTest(row=row), self.assertRaises(qualification.QualificationFailure):
                qualification.require_reproduction(case, row)

    def test_repaired_empty_noop_changed_output_and_residual_errors_fail(self):
        for case in qualification.CASES:
            qualification.require_repaired(case, result(0, stdout=case.expected))
            for row in (result(0), result(1, stdout=case.expected), result(0, stderr='Sanitizer', stdout=case.expected), result(0, stdout=case.expected + 'other')):
                with self.subTest(case=case.number, row=row), self.assertRaises(qualification.QualificationFailure):
                    qualification.require_repaired(case, row)

    def test_all_corrected_sanitizer_builds_include_runtime_instrumentation(self):
        for case in qualification.CASES:
            flags = qualification.compiler_flags(case, True)
            self.assertTrue(any(f.startswith('-fsanitize=') for f in flags), case.cwe)
            self.assertIn('-Werror', flags)
        self.assertIn('-fsanitize=address,undefined,unsigned-integer-overflow', qualification.compiler_flags(qualification.CASES[5], True))


class InvocationControls(unittest.TestCase):
    def setUp(self):
        (ROOT / 'build').mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='cvul-controls-', dir=ROOT / 'build')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def invoke(self, source):
        return qualification.run([sys.executable, '-c', source], self.directory, 'authored-control')

    def test_nonzero_exit_is_retained_for_the_evidence_classifier(self):
        row = self.invoke('import sys; print("diagnostic", file=sys.stderr); sys.exit(1)')
        self.assertEqual(1, row['exitCode'])
        self.assertEqual('diagnostic\n', row['stderr'])
        self.assertEqual(64, len(row['stderrSha256']))

    def test_timeout_is_refused_despite_preprinted_diagnostic(self):
        with patch.object(qualification, 'TIMEOUT_SECONDS', 0.2), self.assertRaisesRegex(qualification.QualificationFailure, 'deadline'):
            self.invoke('import sys,time; print("Sanitizer",flush=True); time.sleep(60)')

    def test_output_overflow_is_capped_and_refused(self):
        with self.assertRaisesRegex(qualification.QualificationFailure, 'output limit'):
            self.invoke('import os; os.write(1,b"x"*1048578)')
        self.assertLessEqual((self.directory / 'authored-control.stdout').stat().st_size, qualification.MAX_STREAM_BYTES + 1)

    def test_signals_and_reserved_invocation_statuses_are_refused(self):
        for code in (124, 125, 126, 127, 137, 153):
            with self.subTest(code=code), self.assertRaisesRegex(qualification.QualificationFailure, 'incomplete'):
                self.invoke(f'import sys; sys.exit({code})')
        with self.assertRaisesRegex(qualification.QualificationFailure, 'incomplete'):
            self.invoke('import os,signal; os.kill(os.getpid(),signal.SIGTERM)')


if __name__ == '__main__':
    unittest.main()
