#!/usr/bin/env python3
"""Unprivileged registration-restoration protocol tests; no kernel qualification."""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture = load("reset_registration_fixture", "ci-oracle-ext4-reset.py")
parser = load("reset_registration_protocol", "oracle-ext4-reset.py")


class RegistrationRefusalTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="reset-registration-controls-", dir=ROOT / "build")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.private = self.directory / "private"
        self.private.mkdir()
        self.gate = self.directory / "public" / "g-0000000000000000"
        (self.gate / "scratch").mkdir(parents=True)
        self.original_path = self.private / "state.json"
        self.saved_path = self.private / "fixture-old-state"
        # These are deliberately protocol inputs, not claimed authenticated state.
        # Root ownership/admission/loop/service authority are outside this suite.
        self.record = {"phase": "REGISTERED", "generation": 0, "candidate": None,
                       "old": {"generation": 0}, "submission": {"invocation": None}}
        self.original_bytes = parser.canonical(self.record)
        self.original_path.write_bytes(self.original_bytes)
        self.original_inode = self.original_path.stat().st_ino
        self.lock_depth = 0
        self.registration_descriptors = set()
        self.service = {"ActiveState": "inactive", "SubState": "dead", "Job": "0",
                        "InvocationID": "", "ExecMainPID": "0", "ExecMainCode": "0",
                        "ExecMainStatus": "0", "Result": "success"}
        self.module = SimpleNamespace(
            opened_store=self.opened_store, parse_record=json.loads,
            parse_canonical=parser.parse_canonical, file_identity=parser.file_identity,
            fd_identity=parser.fd_identity, _entries=parser._entries,
            generation_path=lambda generation: self.gate if generation == 0 else self.fail("unexpected generation"),
            verify_base=Mock(), inactive_snapshot=Mock(return_value=self.service.copy()),
        )
        active = {"caseId": "K27", "events": [], "observations": {"attempts": [], "facts": {}},
                  "formatterCount": 0}
        self.case = fixture.Case({"active": active}, "K27")
        self.case.no_oracle_probe = Mock()
        self.case.broker = Mock(side_effect=AssertionError("state-dependent broker wrapper must not run"))

    @contextlib.contextmanager
    def opened_store(self):
        self.assertEqual(self.lock_depth, 0, "core lock recursively acquired")
        self.lock_depth += 1
        private_fd = os.open(self.private, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors = {private_fd}

        def open_dir(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            descriptors.add(fd)
            return fd

        def drop(fd):
            os.close(fd)
            descriptors.remove(fd)

        store = SimpleNamespace(private=private_fd, load=lambda: json.loads(self.original_path.read_bytes()),
                                open_dir=open_dir, drop=drop)
        try:
            yield store
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
            self.lock_depth -= 1

    def invoke(self, *, code=1, error="[Errno 2] No such file or directory: 'state.json'", during_child=None):
        real_open = os.open

        def tracked_open(path, flags, *arguments, **keywords):
            descriptor = real_open(path, flags, *arguments, **keywords)
            if path == self.original_path:
                self.registration_descriptors.add(descriptor)
            return descriptor

        def bounded_read(path, maximum):
            self.assertTrue(path.is_relative_to(self.private))
            payload = path.read_bytes()
            self.assertLessEqual(len(payload), maximum)
            return payload

        process = SimpleNamespace(returncode=code)
        paced = []

        def launch(argv, **keywords):
            self.assertEqual(paced, [True], 'missing-registration submission was not durably paced first')
            self.assertEqual(self.lock_depth, 0, "broker was invoked while injector held root lock")
            self.assertFalse(self.original_path.exists(), "broker did not see missing registration")
            self.assertEqual(self.saved_path.stat().st_ino, self.original_inode)
            self.assertEqual(self.saved_path.read_bytes(), self.original_bytes)
            self.assertEqual(argv, ["/usr/bin/python3", "-I", "-S", str(self.private / "oracle-ext4-reset.py"), "request", "0"])
            self.assertTrue(keywords["close_fds"])
            if during_child:
                during_child()
            return process

        response = parser.canonical({"ok": False, "error": error, "disposition": "RESERVED"}) + b"\n"
        with patch.object(fixture, "PRIVATE", self.private), \
             patch.object(fixture, "CORE", self.private / "oracle-ext4-reset.py"), \
             patch.object(fixture, "core", return_value=self.module), \
             patch.object(fixture, "pace_submission", side_effect=lambda: paced.append(True)) as pace, \
             patch.object(fixture, "read_regular", side_effect=bounded_read), \
             patch.object(fixture.os, "open", side_effect=tracked_open), \
             patch.object(fixture.subprocess, "Popen", side_effect=launch) as launched, \
             patch.object(fixture, "collect_process", return_value=(code, response, b"")) as collected:
            self.case.missing_registration_refusal()
        launched.assert_called_once()
        pace.assert_called_once_with()
        collected.assert_called_once_with(process)
        self.case.broker.assert_not_called()

    def assert_registration_descriptors_closed(self):
        self.assertTrue(self.registration_descriptors)
        for descriptor in self.registration_descriptors:
            with self.subTest(descriptor=descriptor), self.assertRaises(OSError):
                os.fstat(descriptor)

    def assert_exact_restoration(self):
        self.assertEqual(self.original_path.stat().st_ino, self.original_inode)
        self.assertEqual(self.original_path.read_bytes(), self.original_bytes)
        self.assertFalse(self.saved_path.exists())
        self.assertEqual(self.lock_depth, 0)
        self.assert_registration_descriptors_closed()

    def test_missing_registration_invokes_closed_broker_unlocked_then_restores_exact_inode_and_bytes(self):
        self.invoke()
        self.assert_exact_restoration()
        facts = self.case.observations["facts"]
        self.assertTrue(facts["missingRegistrationRefused"])
        self.assertTrue(facts["registrationRestored"])
        self.assertEqual(facts["registrationBeforeSha256"], facts["registrationAfterSha256"])
        self.assertEqual(self.case.events[0]["details"]["missingRegistration"], True)
        self.assertEqual(self.case.observations["attempts"][0]["exitCode"], 1)

    def test_contention_or_other_refusal_is_not_credited_and_registration_is_restored(self):
        with self.assertRaisesRegex(fixture.QualificationError, "reason other than"):
            self.invoke(error="authority lock is held")
        self.assert_exact_restoration()
        self.assertEqual(self.case.observations["facts"], {})
        self.assertEqual(self.case.observations["attempts"], [])

    def test_unexpected_broker_success_is_not_credited_and_registration_is_restored(self):
        with self.assertRaisesRegex(fixture.QualificationError, "actual bounded broker refusal"):
            self.invoke(code=0)
        self.assert_exact_restoration()
        self.assertEqual(self.case.observations["facts"], {})

    def test_unknown_replacement_is_preserved_without_overwriting_saved_registration(self):
        replacement = b"unrelated replacement canary"
        with self.assertRaisesRegex(fixture.QualificationError, "already occupied"):
            self.invoke(during_child=lambda: self.original_path.write_bytes(replacement))
        self.assertEqual(self.original_path.read_bytes(), replacement)
        self.assertEqual(self.saved_path.stat().st_ino, self.original_inode)
        self.assertEqual(self.saved_path.read_bytes(), self.original_bytes)
        self.assertEqual(self.lock_depth, 0)
        self.assert_registration_descriptors_closed()
        self.assertEqual(self.case.observations["facts"], {})

    def test_changed_service_prevents_restore_and_preserves_saved_registration(self):
        changed = dict(self.service, InvocationID="f" * 32)
        self.module.inactive_snapshot.side_effect = [self.service, changed]
        with self.assertRaisesRegex(fixture.QualificationError, "changed a service invocation"):
            self.invoke()
        self.assertFalse(self.original_path.exists())
        self.assertEqual(self.saved_path.stat().st_ino, self.original_inode)
        self.assertEqual(self.saved_path.read_bytes(), self.original_bytes)
        self.assert_registration_descriptors_closed()
        self.assertEqual(self.case.observations["facts"], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
