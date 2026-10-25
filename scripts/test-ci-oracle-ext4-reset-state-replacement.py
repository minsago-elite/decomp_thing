#!/usr/bin/env python3
"""State replacement protocol controls using local files, not kernel qualification."""
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
CANARY = b"owned-ext4-reset-qualification-canary-v1\n"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture = load("state_replacement_fixture", "ci-oracle-ext4-reset.py")
parser = load("state_replacement_protocol", "oracle-ext4-reset.py")


class StateReplacementRefusalTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "build").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="reset-state-replacement-controls-", dir=ROOT / "build")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.private = self.directory / "private"
        self.private.mkdir()
        self.path = self.private / "state.json"
        self.saved = self.private / "fixture-old-state"
        self.gate = self.directory / "public" / "g-0000000000000000"
        self.scratch = self.gate / "scratch"
        self.scratch.mkdir(parents=True)
        # Synthetic protocol records, not authenticated root/mount/service evidence.
        self.record = {"phase": "REGISTERED", "generation": 0, "candidate": None,
                       "old": {"generation": 0, "mount": {"id": 10}}, "submission": {"invocation": None}}
        self.original = parser.canonical(self.record)
        self.path.write_bytes(self.original)
        self.original_inode = self.path.stat().st_ino
        self.mount = {"id": 10, "path": str(self.scratch), "device": "7:1", "type": "ext4"}
        self.service = {"ActiveState": "inactive", "SubState": "dead", "Job": "0", "InvocationID": "",
                        "ExecMainPID": "0", "ExecMainCode": "0", "ExecMainStatus": "0", "Result": "success"}
        self.lock_depth = 0
        self.descriptors = set()
        self.after_restore = None
        self.module = SimpleNamespace(
            opened_store=self.opened_store, parse_record=json.loads, parse_canonical=parser.parse_canonical,
            file_identity=parser.file_identity, fd_identity=parser.fd_identity,
            generation_path=lambda generation: self.gate,
            current_inventory=lambda record, allowed: [self.mount.copy()],
            mount_at=lambda rows, path: rows[0].copy(), verify_base=Mock(),
            inactive_snapshot=Mock(side_effect=lambda *args: self.service.copy()),
        )
        active = {"caseId": "K25", "events": [], "observations": {"attempts": [], "facts": {}, "canaries": []},
                  "formatterCount": 0}
        self.case = fixture.Case({"active": active}, "K25")
        self.case.no_oracle_probe = Mock()
        self.case.broker = Mock(side_effect=AssertionError("state-dependent broker wrapper called"))
        self.case.mutation = Mock(side_effect=self.mutation)

    @contextlib.contextmanager
    def opened_store(self):
        self.assertEqual(self.lock_depth, 0)
        self.lock_depth += 1

        def read_state():
            self.assertNotEqual(self.path.read_bytes(), CANARY, "state loader ran on invalid replacement")
            return json.loads(self.path.read_bytes())

        try:
            yield SimpleNamespace(load=read_state)
        finally:
            self.lock_depth -= 1

    @contextlib.contextmanager
    def mutation(self, name):
        self.assertEqual(name, "state_anchor_replacement")
        self.assertEqual(self.lock_depth, 0)
        self.assertEqual(json.loads(self.path.read_bytes()), self.record, "mutation constructed after corruption")
        original_identity = parser.file_identity(self.path)
        os.rename(self.path, self.saved)
        self.path.write_bytes(CANARY)
        replacement_identity = parser.file_identity(self.path)
        facts = {"kind": "state-anchor-replacement", "original": original_identity,
                 "replacement": replacement_identity, "canaryBeforeSha256": fixture.digest(CANARY)}
        try:
            yield facts
        finally:
            # This test stand-in only restores its exact owned canary. It never
            # asserts root authority, mount admission, or actual kernel success.
            if parser.file_identity(self.path) == replacement_identity and self.path.read_bytes() == CANARY:
                facts["canaryAfterSha256"] = fixture.digest(self.path.read_bytes())
                self.path.unlink()
                os.rename(self.saved, self.path)
                facts["cleanup"] = True
                if self.after_restore:
                    self.after_restore()

    def invoke(self, *, code=1, error="invalid JSON", during_child=None):
        real_open = os.open

        def tracked_open(path, flags, *arguments, **keywords):
            descriptor = real_open(path, flags, *arguments, **keywords)
            if path == self.path:
                self.descriptors.add(descriptor)
            return descriptor

        def bounded_read(path, maximum):
            self.assertTrue(path.is_relative_to(self.private))
            data = path.read_bytes()
            self.assertLessEqual(len(data), maximum)
            return data

        process = SimpleNamespace(returncode=code)

        def launch(argv, **keywords):
            paced.assert_called_once_with()
            self.assertEqual(self.lock_depth, 0)
            self.assertEqual(self.path.read_bytes(), CANARY)
            self.assertEqual(self.saved.stat().st_ino, self.original_inode)
            self.assertEqual(argv, ["/usr/bin/python3", "-I", "-S", str(self.private / "oracle-ext4-reset.py"), "request", "0"])
            self.assertTrue(keywords["close_fds"])
            if during_child:
                during_child()
            return process

        response = parser.canonical({"ok": False, "error": error, "disposition": "RESERVED"}) + b"\n"
        with patch.object(fixture, "PRIVATE", self.private), \
             patch.object(fixture, "CORE", self.private / "oracle-ext4-reset.py"), \
             patch.object(fixture, "core", return_value=self.module), \
             patch.object(fixture, "state", side_effect=AssertionError("state wrapper used")), \
             patch.object(fixture, "read_regular", side_effect=bounded_read), \
             patch.object(fixture, "pace_submission") as paced, \
             patch.object(fixture.os, "open", side_effect=tracked_open), \
             patch.object(fixture.subprocess, "Popen", side_effect=launch) as launched, \
             patch.object(fixture, "collect_process", return_value=(code, response, b"")):
            self.case.replaced_state_refusal()
        launched.assert_called_once()
        self.case.broker.assert_not_called()
        self.case.mutation.assert_called_once_with("state_anchor_replacement")

    def assert_closed_and_uncredited(self):
        self.assertEqual(self.lock_depth, 0)
        self.assertTrue(self.descriptors)
        for descriptor in self.descriptors:
            with self.subTest(descriptor=descriptor), self.assertRaises(OSError):
                os.fstat(descriptor)
        self.assertEqual(self.case.observations["facts"], {})
        self.assertEqual(self.case.observations["attempts"], [])
        self.assertEqual(self.case.events, [])

    def assert_exact_restoration(self):
        self.assertEqual(self.path.stat().st_ino, self.original_inode)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(self.saved.exists())

    def test_fixed_canary_reaches_paced_raw_broker_and_exact_restoration_is_required_for_credit(self):
        self.invoke()
        self.assert_exact_restoration()
        self.assertEqual(self.case.observations["facts"], {"stateAnchorReplacementRefused": True, "stateAnchorRestored": True})
        self.assertEqual(self.case.observations["attempts"][0]["exitCode"], 1)
        self.assertEqual(self.case.observations["canaries"][0]["beforeSha256"], fixture.digest(CANARY))
        self.assertEqual(self.case.events[0]["details"]["reason"], "state-anchor-replacement")

    def test_wrong_refusal_reason_does_not_earn_credit(self):
        with self.assertRaisesRegex(fixture.QualificationError, "reason other than"):
            self.invoke(error="authority lock is held")
        self.assert_exact_restoration()
        self.assert_closed_and_uncredited()

    def test_unexpected_broker_success_does_not_earn_credit(self):
        with self.assertRaisesRegex(fixture.QualificationError, "actual bounded broker refusal"):
            self.invoke(code=0)
        self.assert_exact_restoration()
        self.assert_closed_and_uncredited()

    def test_changed_original_bytes_during_refusal_are_detected(self):
        altered = self.original + b" "
        with self.assertRaisesRegex(fixture.QualificationError, "changed original registration"):
            self.invoke(during_child=lambda: self.saved.write_bytes(altered))
        self.assertEqual(self.path.stat().st_ino, self.original_inode)
        self.assertEqual(self.path.read_bytes(), altered)
        self.assert_closed_and_uncredited()

    def test_service_drift_is_not_credited(self):
        with self.assertRaisesRegex(fixture.QualificationError, "changed service, gate, mount"):
            self.invoke(during_child=lambda: self.service.update(InvocationID="f" * 32))
        self.assert_exact_restoration()
        self.assert_closed_and_uncredited()

    def test_mount_drift_is_not_credited(self):
        with self.assertRaisesRegex(fixture.QualificationError, "changed service, gate, mount"):
            self.invoke(during_child=lambda: self.mount.update(id=11))
        self.assert_exact_restoration()
        self.assert_closed_and_uncredited()

    def test_new_diagnostic_evidence_is_preserved_and_not_credited(self):
        trace = self.private / "formatter.trace"
        with self.assertRaisesRegex(fixture.QualificationError, "changed service, gate, mount"):
            self.invoke(during_child=lambda: trace.write_bytes(b"unexpected formatter evidence"))
        self.assertEqual(trace.read_bytes(), b"unexpected formatter evidence")
        self.assert_exact_restoration()
        self.assert_closed_and_uncredited()

    def test_changed_restored_state_is_not_credited(self):
        self.after_restore = lambda: self.path.write_bytes(self.original + b" ")
        with self.assertRaisesRegex(fixture.QualificationError, "restore the exact original"):
            self.invoke()
        self.assert_closed_and_uncredited()

    def test_unknown_replacement_preserves_both_unknown_path_and_saved_original_without_credit(self):
        displaced = self.private / "displaced-canary"
        unknown = b"unknown replacement must be preserved"

        def replace_canary():
            os.rename(self.path, displaced)
            self.path.write_bytes(unknown)
            self.assertNotEqual(self.path.stat().st_ino, displaced.stat().st_ino)

        with self.assertRaisesRegex(fixture.QualificationError, "changed original registration or its canary"):
            self.invoke(during_child=replace_canary)
        self.assertEqual(self.path.read_bytes(), unknown)
        self.assertEqual(self.saved.stat().st_ino, self.original_inode)
        self.assertEqual(self.saved.read_bytes(), self.original)
        self.assertEqual(displaced.read_bytes(), CANARY)
        self.assert_closed_and_uncredited()


if __name__ == "__main__":
    unittest.main(verbosity=2)
